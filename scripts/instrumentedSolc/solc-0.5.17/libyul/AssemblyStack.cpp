/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * Full assembly stack that can support EVM-assembly and Yul as input and EVM, EVM1.5 and
 * eWasm as output.
 */


#include <libyul/AssemblyStack.h>

#include <libyul/AsmAnalysis.h>
#include <libyul/AsmAnalysisInfo.h>
#include <libyul/AsmParser.h>
#include <libyul/AsmPrinter.h>
#include <libyul/backends/evm/AsmCodeGen.h>
#include <libyul/backends/evm/EVMAssembly.h>
#include <libyul/backends/evm/EVMCodeTransform.h>
#include <libyul/backends/evm/EVMDialect.h>
#include <libyul/backends/evm/EVMObjectCompiler.h>
#include <libyul/backends/evm/EVMMetrics.h>
#include <libyul/backends/wasm/WasmDialect.h>
#include <libyul/backends/wasm/EWasmObjectCompiler.h>
#include <libyul/backends/wasm/EVMToEWasmTranslator.h>
#include <libyul/optimiser/Metrics.h>
#include <libyul/ObjectParser.h>
#include <libyul/optimiser/Suite.h>

#include <libsolidity/interface/OptimiserSettings.h>

#include <libevmasm/Assembly.h>
#include <liblangutil/Scanner.h>

using namespace std;
using namespace langutil;
using namespace yul;

namespace
{
Dialect const& languageToDialect(AssemblyStack::Language _language, EVMVersion _version)
{
	switch (_language)
	{
	case AssemblyStack::Language::Assembly:
		return EVMDialect::looseAssemblyForEVM(_version);
	case AssemblyStack::Language::StrictAssembly:
		return EVMDialect::strictAssemblyForEVMObjects(_version);
	case AssemblyStack::Language::Yul:
		return Dialect::yul();
	case AssemblyStack::Language::EWasm:
		return WasmDialect::instance();
	}
	yulAssert(false, "");
	return Dialect::yul();
}

}


Scanner const& AssemblyStack::scanner() const
{
	yulAssert(m_scanner, "");
	return *m_scanner;
}

bool AssemblyStack::parseAndAnalyze(std::string const& _sourceName, std::string const& _source)
{
	m_errors.clear();
	m_analysisSuccessful = false;
	m_scanner = make_shared<Scanner>(CharStream(_source, _sourceName));
	m_parserResult = ObjectParser(m_errorReporter, languageToDialect(m_language, m_evmVersion)).parse(m_scanner, false);
	if (!m_errorReporter.errors().empty())
		return false;
	yulAssert(m_parserResult, "");
	yulAssert(m_parserResult->code, "");

	return analyzeParsed();
}

void AssemblyStack::optimize()
{
	if (!m_optimiserSettings.runYulOptimiser)
		return;

	yulAssert(m_analysisSuccessful, "Analysis was not successful.");

	m_analysisSuccessful = false;
	yulAssert(m_parserResult, "");
	optimize(*m_parserResult, true);
	yulAssert(analyzeParsed(), "Invalid source code after optimization.");
}

void AssemblyStack::translate(AssemblyStack::Language _targetLanguage)
{
	if (m_language == _targetLanguage)
		return;

	solAssert(
		m_language == Language::StrictAssembly && _targetLanguage == Language::EWasm,
		"Invalid language combination"
	);

	*m_parserResult = EVMToEWasmTranslator(
		languageToDialect(m_language, m_evmVersion)
	).run(*parserResult());

	m_language = _targetLanguage;
}

bool AssemblyStack::analyzeParsed()
{
	yulAssert(m_parserResult, "");
	m_analysisSuccessful = analyzeParsed(*m_parserResult);
	return m_analysisSuccessful;
}

bool AssemblyStack::analyzeParsed(Object& _object)
{
	yulAssert(_object.code, "");
	_object.analysisInfo = make_shared<AsmAnalysisInfo>();

	AsmAnalyzer analyzer(
		*_object.analysisInfo,
		m_errorReporter,
		std::nullopt,
		languageToDialect(m_language, m_evmVersion),
		{},
		_object.dataNames()
	);
	bool success = analyzer.analyze(*_object.code);
	for (auto& subNode: _object.subObjects)
		if (auto subObject = dynamic_cast<Object*>(subNode.get()))
			if (!analyzeParsed(*subObject))
				success = false;
	return success;
}

void AssemblyStack::compileEVM(AbstractAssembly& _assembly, bool _evm15, bool _optimize) const
{
	EVMDialect const* dialect = nullptr;

	if (m_language == Language::Assembly)
		dialect = &EVMDialect::looseAssemblyForEVM(m_evmVersion);
	else if (m_language == AssemblyStack::Language::StrictAssembly)
		dialect = &EVMDialect::strictAssemblyForEVMObjects(m_evmVersion);
	else if (m_language == AssemblyStack::Language::Yul)
		dialect = &EVMDialect::yulForEVM(m_evmVersion);
	else
		yulAssert(false, "Invalid language.");

	EVMObjectCompiler::compile(*m_parserResult, _assembly, *dialect, _evm15, _optimize);
}

void AssemblyStack::optimize(Object& _object, bool _isCreation)
{
	yulAssert(_object.code, "");
	yulAssert(_object.analysisInfo, "");
	for (auto& subNode: _object.subObjects)
		if (auto subObject = dynamic_cast<Object*>(subNode.get()))
			optimize(*subObject, false);

	Dialect const& dialect = languageToDialect(m_language, m_evmVersion);
	unique_ptr<GasMeter> meter;
	if (EVMDialect const* evmDialect = dynamic_cast<EVMDialect const*>(&dialect))
		meter = make_unique<GasMeter>(*evmDialect, _isCreation, m_optimiserSettings.expectedExecutionsPerDeployment);
	OptimiserSuite::run(
		dialect,
		meter.get(),
		_object,
		m_optimiserSettings.optimizeStackAllocation
	);
}

MachineAssemblyObject AssemblyStack::assemble(Machine _machine) const
{
	yulAssert(m_analysisSuccessful, "");
	yulAssert(m_parserResult, "");
	yulAssert(m_parserResult->code, "");
	yulAssert(m_parserResult->analysisInfo, "");

	switch (_machine)
	{
	case Machine::EVM:
	{
		MachineAssemblyObject object;
		dev::eth::Assembly assembly;
		EthAssemblyAdapter adapter(assembly);
		compileEVM(adapter, false, m_optimiserSettings.optimizeStackAllocation);
		object.bytecode = make_shared<dev::eth::LinkerObject>(assembly.assemble());
		object.assembly = assembly.assemblyString();
		return object;
	}
	case Machine::EVM15:
	{
		MachineAssemblyObject object;
		EVMAssembly assembly(true);
		compileEVM(assembly, true, m_optimiserSettings.optimizeStackAllocation);
		object.bytecode = make_shared<dev::eth::LinkerObject>(assembly.finalize());
		/// TODO: fill out text representation
		return object;
	}
	case Machine::eWasm:
	{
		yulAssert(m_language == Language::EWasm, "");
		Dialect const& dialect = languageToDialect(m_language, EVMVersion{});

		MachineAssemblyObject object;
		auto result = EWasmObjectCompiler::compile(*m_parserResult, dialect);
		object.assembly = std::move(result.first);
		object.bytecode = make_shared<dev::eth::LinkerObject>();
		object.bytecode->bytecode = std::move(result.second);
		return object;
	}
	}
	// unreachable
	return MachineAssemblyObject();
}

string AssemblyStack::print() const
{
	yulAssert(m_parserResult, "");
	yulAssert(m_parserResult->code, "");
	return m_parserResult->toString(m_language == Language::Yul) + "\n";
}

shared_ptr<Object> AssemblyStack::parserResult() const
{
	yulAssert(m_analysisSuccessful, "Analysis was not successful.");
	yulAssert(m_parserResult, "");
	yulAssert(m_parserResult->code, "");
	return m_parserResult;
}
