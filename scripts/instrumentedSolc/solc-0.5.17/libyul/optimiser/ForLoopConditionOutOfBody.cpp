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

#include <libyul/optimiser/ForLoopConditionOutOfBody.h>
#include <libyul/optimiser/Semantics.h>
#include <libyul/AsmData.h>
#include <libyul/Utilities.h>
#include <libdevcore/CommonData.h>

using namespace std;
using namespace dev;
using namespace yul;

void ForLoopConditionOutOfBody::run(OptimiserStepContext& _context, Block& _ast)
{
	ForLoopConditionOutOfBody{_context.dialect}(_ast);
}

void ForLoopConditionOutOfBody::operator()(ForLoop& _forLoop)
{
	ASTModifier::operator()(_forLoop);

	if (
		!m_dialect.booleanNegationFunction() ||
		!holds_alternative<Literal>(*_forLoop.condition) ||
		valueOfLiteral(std::get<Literal>(*_forLoop.condition)) == u256(0) ||
		_forLoop.body.statements.empty() ||
		!holds_alternative<If>(_forLoop.body.statements.front())
	)
		return;

	If& firstStatement = std::get<If>(_forLoop.body.statements.front());
	if (
		firstStatement.body.statements.empty() ||
		!holds_alternative<Break>(firstStatement.body.statements.front())
	)
		return;
	if (!SideEffectsCollector(m_dialect, *firstStatement.condition).movable())
		return;

	YulString iszero = m_dialect.booleanNegationFunction()->name;
	langutil::SourceLocation location = locationOf(*firstStatement.condition);

	if (
		holds_alternative<FunctionCall>(*firstStatement.condition) &&
		std::get<FunctionCall>(*firstStatement.condition).functionName.name == iszero
	)
		_forLoop.condition = make_unique<Expression>(std::move(std::get<FunctionCall>(*firstStatement.condition).arguments.front()));
	else
		_forLoop.condition = make_unique<Expression>(FunctionCall{
			location,
			Identifier{location, iszero},
			make_vector<Expression>(
				std::move(*firstStatement.condition)
			)
		});

	_forLoop.body.statements.erase(_forLoop.body.statements.begin());
}

