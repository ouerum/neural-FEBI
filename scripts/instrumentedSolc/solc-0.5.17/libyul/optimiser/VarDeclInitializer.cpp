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

#include <libyul/optimiser/VarDeclInitializer.h>
#include <libyul/AsmData.h>

#include <libdevcore/CommonData.h>
#include <libdevcore/Visitor.h>

using namespace std;
using namespace dev;
using namespace yul;

void VarDeclInitializer::operator()(Block& _block)
{
	ASTModifier::operator()(_block);

	using OptionalStatements = std::optional<vector<Statement>>;
	GenericVisitor visitor{
		VisitorFallback<OptionalStatements>{},
		[](VariableDeclaration& _varDecl) -> OptionalStatements
		{
			if (_varDecl.value)
				return {};
			Literal zero{{}, LiteralKind::Number, YulString{"0"}, {}};
			if (_varDecl.variables.size() == 1)
			{
				_varDecl.value = make_unique<Expression>(std::move(zero));
				return {};
			}
			else
			{
				OptionalStatements ret{vector<Statement>{}};
				langutil::SourceLocation loc{std::move(_varDecl.location)};
				for (auto& var: _varDecl.variables)
					ret->emplace_back(VariableDeclaration{loc, {std::move(var)}, make_unique<Expression>(zero)});
				return ret;
			}
		}
	};

	iterateReplacing(_block.statements, [&](auto&& _statement) { return std::visit(visitor, _statement); });
}
