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
 * Specific AST copier that replaces certain identifiers with expressions.
 */

#pragma once

#include <libjulia/optimiser/ASTCopier.h>

#include <string>
#include <map>
#include <set>

namespace dev
{
namespace julia
{

/**
 * Specific AST copier that replaces certain identifiers with expressions.
 */
class Substitution: public ASTCopier
{
public:
	Substitution(std::map<std::string, Expression const*> const& _substitutions):
		m_substitutions(_substitutions)
	{}
	virtual Expression translate(Expression const& _expression) override;

private:
	std::map<std::string, Expression const*> const& m_substitutions;
};

}
}
