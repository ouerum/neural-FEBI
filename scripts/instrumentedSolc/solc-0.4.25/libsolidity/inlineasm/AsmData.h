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
 * @author Christian <c@ethdev.com>
 * @date 2016
 * Parsed inline assembly to be used by the AST
 */

#pragma once

#include <libsolidity/inlineasm/AsmDataForward.h>

#include <libevmasm/Instruction.h>
#include <libevmasm/SourceLocation.h>

#include <boost/variant.hpp>

namespace dev
{
namespace solidity
{
namespace assembly
{

using Type = std::string;

struct TypedName { SourceLocation location; std::string name; Type type; };
using TypedNameList = std::vector<TypedName>;

/// Direct EVM instruction (except PUSHi and JUMPDEST)
struct Instruction { SourceLocation location; solidity::Instruction instruction; };
/// Literal number or string (up to 32 bytes)
enum class LiteralKind { Number, Boolean, String };
struct Literal { SourceLocation location; LiteralKind kind; std::string value; Type type; };
/// External / internal identifier or label reference
struct Identifier { SourceLocation location; std::string name; };
/// Jump label ("name:")
struct Label { SourceLocation location; std::string name; };
/// Assignment from stack (":= x", moves stack top into x, potentially multiple slots)
struct StackAssignment { SourceLocation location; Identifier variableName; };
/// Assignment ("x := mload(20:u256)", expects push-1-expression on the right hand
/// side and requires x to occupy exactly one stack slot.
///
/// Multiple assignment ("x, y := f()"), where the left hand side variables each occupy
/// a single stack slot and expects a single expression on the right hand returning
/// the same amount of items as the number of variables.
struct Assignment { SourceLocation location; std::vector<Identifier> variableNames; std::shared_ptr<Expression> value; };
/// Functional instruction, e.g. "mul(mload(20:u256), add(2:u256, x))"
struct FunctionalInstruction { SourceLocation location; solidity::Instruction instruction; std::vector<Expression> arguments; };
struct FunctionCall { SourceLocation location; Identifier functionName; std::vector<Expression> arguments; };
/// Statement that contains only a single expression
struct ExpressionStatement { SourceLocation location; Expression expression; };
/// Block-scope variable declaration ("let x:u256 := mload(20:u256)"), non-hoisted
struct VariableDeclaration { SourceLocation location; TypedNameList variables; std::shared_ptr<Expression> value; };
/// Block that creates a scope (frees declared stack variables)
struct Block { SourceLocation location; std::vector<Statement> statements; };
/// Function definition ("function f(a, b) -> (d, e) { ... }")
struct FunctionDefinition { SourceLocation location; std::string name; TypedNameList parameters; TypedNameList returnVariables; Block body; };
/// Conditional execution without "else" part.
struct If { SourceLocation location; std::shared_ptr<Expression> condition; Block body; };
/// Switch case or default case
struct Case { SourceLocation location; std::shared_ptr<Literal> value; Block body; };
/// Switch statement
struct Switch { SourceLocation location; std::shared_ptr<Expression> expression; std::vector<Case> cases; };
struct ForLoop { SourceLocation location; Block pre; std::shared_ptr<Expression> condition; Block post; Block body; };

struct LocationExtractor: boost::static_visitor<SourceLocation>
{
	template <class T> SourceLocation operator()(T const& _node) const
	{
		return _node.location;
	}
};

/// Extracts the source location from an inline assembly node.
template <class T> inline SourceLocation locationOf(T const& _node)
{
	return boost::apply_visitor(LocationExtractor(), _node);
}

}
}
}
