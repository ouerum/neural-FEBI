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
 * Optimisation stage that removes unused variables and functions.
 */

#include <libjulia/optimiser/UnusedPruner.h>

#include <libjulia/optimiser/NameCollector.h>
#include <libjulia/optimiser/Semantics.h>
#include <libjulia/optimiser/Utilities.h>
#include <libjulia/Exceptions.h>

#include <libsolidity/inlineasm/AsmData.h>

#include <boost/algorithm/cxx11/none_of.hpp>

using namespace std;
using namespace dev;
using namespace dev::julia;

UnusedPruner::UnusedPruner(Block& _ast)
{
	ReferencesCounter counter;
	counter(_ast);

	m_references = counter.references();
}

void UnusedPruner::operator()(Block& _block)
{
	for (auto&& statement: _block.statements)
		if (statement.type() == typeid(FunctionDefinition))
		{
			FunctionDefinition& funDef = boost::get<FunctionDefinition>(statement);
			if (!used(funDef.name))
			{
				subtractReferences(ReferencesCounter::countReferences(funDef.body));
				statement = Block{std::move(funDef.location), {}};
			}
		}
		else if (statement.type() == typeid(VariableDeclaration))
		{
			VariableDeclaration& varDecl = boost::get<VariableDeclaration>(statement);
			// Multi-variable declarations are special. We can only remove it
			// if all vairables are unused and the right-hand-side is either
			// movable or it return a single value. In the latter case, we
			// replace `let a := f()` by `pop(f())` (in pure IULIA, this will be
			// `drop(f())`).
			if (boost::algorithm::none_of(
				varDecl.variables,
				[=](TypedName const& _typedName) { return used(_typedName.name); }
			))
			{
				if (!varDecl.value)
					statement = Block{std::move(varDecl.location), {}};
				else if (MovableChecker(*varDecl.value).movable())
				{
					subtractReferences(ReferencesCounter::countReferences(*varDecl.value));
					statement = Block{std::move(varDecl.location), {}};
				}
				else if (varDecl.variables.size() == 1)
					// In pure IULIA, this should be replaced by a function call to `drop`
					// instead of `pop`.
					statement = ExpressionStatement{varDecl.location, FunctionalInstruction{
						varDecl.location,
						solidity::Instruction::POP,
						{*std::move(varDecl.value)}
					}};
			}
		}

	removeEmptyBlocks(_block);

	ASTModifier::operator()(_block);
}

void UnusedPruner::runUntilStabilised(Block& _ast)
{
	while (true)
	{
		UnusedPruner pruner(_ast);
		pruner(_ast);
		if (!pruner.shouldRunAgain())
			return;
	}
}

bool UnusedPruner::used(string const& _name) const
{
	return m_references.count(_name) && m_references.at(_name) > 0;
}

void UnusedPruner::subtractReferences(map<string, size_t> const& _subtrahend)
{
	for (auto const& ref: _subtrahend)
	{
		assertThrow(m_references.count(ref.first), OptimizerException, "");
		assertThrow(m_references.at(ref.first) >= ref.second, OptimizerException, "");
		m_references[ref.first] -= ref.second;
		m_shouldRunAgain = true;
	}
}
