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

#include <libyul/AsmData.h>
#include <libyul/backends/wasm/WordSizeTransform.h>
#include <libyul/Utilities.h>
#include <libyul/Dialect.h>
#include <libyul/optimiser/NameDisplacer.h>

#include <libdevcore/CommonData.h>

#include <array>
#include <map>
#include <variant>

using namespace std;
using namespace dev;
using namespace yul;

void WordSizeTransform::operator()(FunctionDefinition& _fd)
{
	rewriteVarDeclList(_fd.parameters);
	rewriteVarDeclList(_fd.returnVariables);
	(*this)(_fd.body);
}

void WordSizeTransform::operator()(FunctionalInstruction& _ins)
{
	rewriteFunctionCallArguments(_ins.arguments);
}

void WordSizeTransform::operator()(FunctionCall& _fc)
{
	if (BuiltinFunction const* fun = m_inputDialect.builtin(_fc.functionName.name))
		if (fun->literalArguments)
			return;

	rewriteFunctionCallArguments(_fc.arguments);
}

void WordSizeTransform::operator()(If& _if)
{
	_if.condition = make_unique<Expression>(FunctionCall{
		locationOf(*_if.condition),
		Identifier{locationOf(*_if.condition), "or_bool"_yulstring},
		expandValueToVector(*_if.condition)
	});
	(*this)(_if.body);
}

void WordSizeTransform::operator()(Switch&)
{
	yulAssert(false, "Switch statement has to be handled inside the containing block.");
}

void WordSizeTransform::operator()(ForLoop& _for)
{
	(*this)(_for.pre);
	_for.condition = make_unique<Expression>(FunctionCall{
		locationOf(*_for.condition),
		Identifier{locationOf(*_for.condition), "or_bool"_yulstring},
		expandValueToVector(*_for.condition)
	});
	(*this)(_for.post);
	(*this)(_for.body);
}

void WordSizeTransform::operator()(Block& _block)
{
	iterateReplacing(
		_block.statements,
		[&](Statement& _s) -> std::optional<vector<Statement>>
		{
			if (holds_alternative<VariableDeclaration>(_s))
			{
				VariableDeclaration& varDecl = std::get<VariableDeclaration>(_s);

				// Special handling for datasize and dataoffset - they will only need one variable.
				if (varDecl.value && holds_alternative<FunctionCall>(*varDecl.value))
					if (BuiltinFunction const* f = m_inputDialect.builtin(std::get<FunctionCall>(*varDecl.value).functionName.name))
						if (f->literalArguments)
						{
							yulAssert(f->name == "datasize"_yulstring || f->name == "dataoffset"_yulstring, "");
							yulAssert(varDecl.variables.size() == 1, "");
							auto newLhs = generateU64IdentifierNames(varDecl.variables[0].name);
							vector<Statement> ret;
							for (int i = 0; i < 3; i++)
								ret.push_back(VariableDeclaration{
									varDecl.location,
									{TypedName{varDecl.location, newLhs[i], "u64"_yulstring}},
									make_unique<Expression>(Literal{locationOf(*varDecl.value), LiteralKind::Number, "0"_yulstring, "u64"_yulstring})
								});
							ret.push_back(VariableDeclaration{
								varDecl.location,
								{TypedName{varDecl.location, newLhs[3], "u64"_yulstring}},
								std::move(varDecl.value)
							});
							return {std::move(ret)};
						}

				if (
					!varDecl.value ||
					holds_alternative<FunctionalInstruction>(*varDecl.value) ||
					holds_alternative<FunctionCall>(*varDecl.value)
				)
				{
					if (varDecl.value) visit(*varDecl.value);
					rewriteVarDeclList(varDecl.variables);
					return std::nullopt;
				}
				else if (
					holds_alternative<Identifier>(*varDecl.value) ||
					holds_alternative<Literal>(*varDecl.value)
				)
				{
					yulAssert(varDecl.variables.size() == 1, "");
					auto newRhs = expandValue(*varDecl.value);
					auto newLhs = generateU64IdentifierNames(varDecl.variables[0].name);
					vector<Statement> ret;
					for (int i = 0; i < 4; i++)
						ret.push_back(
							VariableDeclaration{
								varDecl.location,
								{TypedName{varDecl.location, newLhs[i], "u64"_yulstring}},
								std::move(newRhs[i])
							}
						);
					return {std::move(ret)};
				}
				else
					yulAssert(false, "");
			}
			else if (holds_alternative<Assignment>(_s))
			{
				Assignment& assignment = std::get<Assignment>(_s);
				yulAssert(assignment.value, "");

				// Special handling for datasize and dataoffset - they will only need one variable.
				if (holds_alternative<FunctionCall>(*assignment.value))
					if (BuiltinFunction const* f = m_inputDialect.builtin(std::get<FunctionCall>(*assignment.value).functionName.name))
						if (f->literalArguments)
						{
							yulAssert(f->name == "datasize"_yulstring || f->name == "dataoffset"_yulstring, "");
							yulAssert(assignment.variableNames.size() == 1, "");
							auto newLhs = generateU64IdentifierNames(assignment.variableNames[0].name);
							vector<Statement> ret;
							for (int i = 0; i < 3; i++)
								ret.push_back(Assignment{
									assignment.location,
									{Identifier{assignment.location, newLhs[i]}},
									make_unique<Expression>(Literal{locationOf(*assignment.value), LiteralKind::Number, "0"_yulstring, "u64"_yulstring})
								});
							ret.push_back(Assignment{
								assignment.location,
								{Identifier{assignment.location, newLhs[3]}},
								std::move(assignment.value)
							});
							return {std::move(ret)};
						}

				if (
					holds_alternative<FunctionalInstruction>(*assignment.value) ||
					holds_alternative<FunctionCall>(*assignment.value)
				)
				{
					if (assignment.value) visit(*assignment.value);
					rewriteIdentifierList(assignment.variableNames);
					return std::nullopt;
				}
				else if (
					holds_alternative<Identifier>(*assignment.value) ||
					holds_alternative<Literal>(*assignment.value)
				)
				{
					yulAssert(assignment.variableNames.size() == 1, "");
					auto newRhs = expandValue(*assignment.value);
					YulString lhsName = assignment.variableNames[0].name;
					vector<Statement> ret;
					for (int i = 0; i < 4; i++)
						ret.push_back(
							Assignment{
								assignment.location,
								{Identifier{assignment.location, m_variableMapping.at(lhsName)[i]}},
								std::move(newRhs[i])
							}
						);
					return {std::move(ret)};
				}
				else
					yulAssert(false, "");
			}
			else if (holds_alternative<Switch>(_s))
				return handleSwitch(std::get<Switch>(_s));
			else
				visit(_s);
			return std::nullopt;
		}
	);
}

void WordSizeTransform::run(Dialect const& _inputDialect, Block& _ast, NameDispenser& _nameDispenser)
{
	// Free the name `or_bool`.
	NameDisplacer{_nameDispenser, {"or_bool"_yulstring}}(_ast);
	WordSizeTransform{_inputDialect, _nameDispenser}(_ast);
}

void WordSizeTransform::rewriteVarDeclList(TypedNameList& _nameList)
{
	iterateReplacing(
		_nameList,
		[&](TypedName const& _n) -> std::optional<TypedNameList>
		{
			TypedNameList ret;
			for (auto newName: generateU64IdentifierNames(_n.name))
				ret.emplace_back(TypedName{_n.location, newName, "u64"_yulstring});
			return ret;
		}
	);
}

void WordSizeTransform::rewriteIdentifierList(vector<Identifier>& _ids)
{
	iterateReplacing(
		_ids,
		[&](Identifier const& _id) -> std::optional<vector<Identifier>>
		{
			vector<Identifier> ret;
			for (auto newId: m_variableMapping.at(_id.name))
				ret.push_back(Identifier{_id.location, newId});
			return ret;
		}
	);
}

void WordSizeTransform::rewriteFunctionCallArguments(vector<Expression>& _args)
{
	iterateReplacing(
		_args,
		[&](Expression& _e) -> std::optional<vector<Expression>>
		{
			return expandValueToVector(_e);
		}
	);
}

vector<Statement> WordSizeTransform::handleSwitchInternal(
	langutil::SourceLocation const& _location,
	vector<YulString> const& _splitExpressions,
	vector<Case> _cases,
	YulString _runDefaultFlag,
	size_t _depth
)
{
	if (_depth == 4)
	{
		yulAssert(_cases.size() == 1, "");
		return std::move(_cases.front().body.statements);
	}

	// Extract current 64 bit segment and group by it.
	map<u256, vector<Case>> cases;
	for (Case& c: _cases)
	{
		yulAssert(c.value, "Default case still present.");
		cases[
			(valueOfLiteral(*c.value) >> (256 - 64 * (_depth + 1)))	&
			std::numeric_limits<uint64_t>::max()
		].emplace_back(std::move(c));
	}

	Switch ret{
		_location,
		make_unique<Expression>(Identifier{_location, _splitExpressions.at(_depth)}),
		{}
	};

	for (auto& c: cases)
	{
		Literal label{_location, LiteralKind::Number, YulString(c.first.str()), "u64"_yulstring};
		ret.cases.emplace_back(Case{
			c.second.front().location,
			make_unique<Literal>(std::move(label)),
			Block{_location, handleSwitchInternal(
				_location,
				_splitExpressions,
				std::move(c.second),
				_runDefaultFlag,
				_depth + 1
			)}
		});
	}
	if (!_runDefaultFlag.empty())
		ret.cases.emplace_back(Case{
			_location,
			nullptr,
			Block{_location, make_vector<Statement>(
				Assignment{
					_location,
					{{_location, _runDefaultFlag}},
					make_unique<Expression>(Literal{_location, LiteralKind::Number, "1"_yulstring, "u64"_yulstring})
				}
			)}
		});
	return make_vector<Statement>(std::move(ret));
}

std::vector<Statement> WordSizeTransform::handleSwitch(Switch& _switch)
{
	for (auto& c: _switch.cases)
		(*this)(c.body);

	// Turns the switch into a quadruply-nested switch plus
	// a flag that tells to execute the default case after all the switches.
	vector<Statement> ret;

	YulString runDefaultFlag;
	Case defaultCase;
	if (!_switch.cases.back().value)
	{
		runDefaultFlag = m_nameDispenser.newName("run_default"_yulstring);
		defaultCase = std::move(_switch.cases.back());
		_switch.cases.pop_back();
		ret.emplace_back(VariableDeclaration{
			_switch.location,
			{TypedName{_switch.location, runDefaultFlag, "u64"_yulstring}},
			{}
		});
	}
	vector<YulString> splitExpressions;
	for (auto const& expr: expandValue(*_switch.expression))
		splitExpressions.emplace_back(std::get<Identifier>(*expr).name);

	ret += handleSwitchInternal(
		_switch.location,
		splitExpressions,
		std::move(_switch.cases),
		runDefaultFlag,
		0
	);
	if (!runDefaultFlag.empty())
		ret.emplace_back(If{
			_switch.location,
			make_unique<Expression>(Identifier{_switch.location, runDefaultFlag}),
			std::move(defaultCase.body)
		});
	return ret;
}


array<YulString, 4> WordSizeTransform::generateU64IdentifierNames(YulString const& _s)
{
	yulAssert(m_variableMapping.find(_s) == m_variableMapping.end(), "");
	for (int i = 0; i < 4; i++)
		m_variableMapping[_s][i] = m_nameDispenser.newName(YulString{_s.str() + "_" + to_string(i)});
	return m_variableMapping[_s];
}

array<unique_ptr<Expression>, 4> WordSizeTransform::expandValue(Expression const& _e)
{
	array<unique_ptr<Expression>, 4> ret;
	if (holds_alternative<Identifier>(_e))
	{
		Identifier const& id = std::get<Identifier>(_e);
		for (int i = 0; i < 4; i++)
			ret[i] = make_unique<Expression>(Identifier{id.location, m_variableMapping.at(id.name)[i]});
	}
	else if (holds_alternative<Literal>(_e))
	{
		Literal const& lit = std::get<Literal>(_e);
		u256 val = valueOfLiteral(lit);
		for (int i = 3; i >= 0; i--)
		{
			u256 currentVal = val & std::numeric_limits<uint64_t>::max();
			val >>= 64;
			ret[i] = make_unique<Expression>(
				Literal{
					lit.location,
					LiteralKind::Number,
					YulString(currentVal.str()),
					"u64"_yulstring
				}
			);
		}
	}
	else
		yulAssert(false, "Invalid expression to split.");
	return ret;
}

vector<Expression> WordSizeTransform::expandValueToVector(Expression const& _e)
{
	vector<Expression> ret;
	for (unique_ptr<Expression>& val: expandValue(_e))
		ret.emplace_back(std::move(*val));
	return ret;
}

