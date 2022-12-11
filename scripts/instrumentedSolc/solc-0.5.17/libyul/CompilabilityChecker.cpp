/*(
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
 * Component that checks whether all variables are reachable on the stack.
 */

#include <libyul/CompilabilityChecker.h>

#include <libyul/AsmAnalysis.h>
#include <libyul/AsmAnalysisInfo.h>

#include <libyul/backends/evm/EVMCodeTransform.h>
#include <libyul/backends/evm/NoOutputAssembly.h>

#include <liblangutil/EVMVersion.h>

using namespace std;
using namespace yul;
using namespace dev;

map<YulString, int> CompilabilityChecker::run(
	Dialect const& _dialect,
	Object const& _object,
	bool _optimizeStackAllocation
)
{
	if (_dialect.flavour == AsmFlavour::Yul)
		return {};

	yulAssert(_dialect.flavour == AsmFlavour::Strict, "");

	if (EVMDialect const* evmDialect = dynamic_cast<EVMDialect const*>(&_dialect))
	{
		NoOutputEVMDialect noOutputDialect(*evmDialect);

		yul::AsmAnalysisInfo analysisInfo =
			yul::AsmAnalyzer::analyzeStrictAssertCorrect(noOutputDialect, _object);

		BuiltinContext builtinContext;
		builtinContext.currentObject = &_object;
		for (auto name: _object.dataNames())
			builtinContext.subIDs[name] = 1;
		NoOutputAssembly assembly;
		CodeTransform transform(
			assembly,
			analysisInfo,
			*_object.code,
			noOutputDialect,
			builtinContext,
			_optimizeStackAllocation
		);
		try
		{
			transform(*_object.code);
		}
		catch (StackTooDeepError const&)
		{
			yulAssert(!transform.stackErrors().empty(), "Got stack too deep exception that was not stored.");
		}

		std::map<YulString, int> functions;
		for (StackTooDeepError const& error: transform.stackErrors())
			functions[error.functionName] = max(error.depth, functions[error.functionName]);

		return functions;
	}
	else
		return {};
}
