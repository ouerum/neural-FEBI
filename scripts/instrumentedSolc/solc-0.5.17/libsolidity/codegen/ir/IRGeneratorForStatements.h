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
 * Component that translates Solidity code into Yul at statement level and below.
 */

#pragma once

#include <libsolidity/ast/ASTVisitor.h>
#include <libsolidity/codegen/ir/IRLValue.h>

namespace dev
{
namespace solidity
{

class IRGenerationContext;
class YulUtilFunctions;

/**
 * Component that translates Solidity's AST into Yul at statement level and below.
 * It is an AST visitor that appends to an internal string buffer.
 */
class IRGeneratorForStatements: public ASTConstVisitor
{
public:
	IRGeneratorForStatements(IRGenerationContext& _context, YulUtilFunctions& _utils):
		m_context(_context),
		m_utils(_utils)
	{}

	std::string code() const;

	/// Generates code to initialize the given state variable.
	void initializeStateVar(VariableDeclaration const& _varDecl);

	void endVisit(VariableDeclarationStatement const& _variableDeclaration) override;
	bool visit(Assignment const& _assignment) override;
	bool visit(TupleExpression const& _tuple) override;
	bool visit(IfStatement const& _ifStatement) override;
	bool visit(ForStatement const& _forStatement) override;
	bool visit(WhileStatement const& _whileStatement) override;
	bool visit(Continue const& _continueStatement) override;
	bool visit(Break const& _breakStatement) override;
	void endVisit(Return const& _return) override;
	void endVisit(UnaryOperation const& _unaryOperation) override;
	bool visit(BinaryOperation const& _binOp) override;
	void endVisit(FunctionCall const& _funCall) override;
	void endVisit(MemberAccess const& _memberAccess) override;
	bool visit(InlineAssembly const& _inlineAsm) override;
	void endVisit(IndexAccess const& _indexAccess) override;
	void endVisit(Identifier const& _identifier) override;
	bool visit(Literal const& _literal) override;

private:
	/// Appends code to call an external function with the given arguments.
	/// All involved expressions have already been visited.
	void appendExternalFunctionCall(
		FunctionCall const& _functionCall,
		std::vector<ASTPointer<Expression const>> const& _arguments
	);

	std::string fetchFreeMem() const;

	/// @returns a Yul expression representing the current value of @a _expression,
	/// converted to type @a _to if it does not yet have that type.
	std::string expressionAsType(Expression const& _expression, Type const& _to);
	std::ostream& defineExpression(Expression const& _expression);
	/// Defines only one of many variables corresponding to an expression.
	/// We start counting at 1 instead of 0.
	std::ostream& defineExpressionPart(Expression const& _expression, size_t _part);

	void appendAndOrOperatorCode(BinaryOperation const& _binOp);
	void appendSimpleUnaryOperation(UnaryOperation const& _operation, Expression const& _expr);

	/// @returns code to perform the given binary operation in the given type on the two values.
	std::string binaryOperation(
		langutil::Token _op,
		Type const& _type,
		std::string const& _left,
		std::string const& _right
	);

	void setLValue(Expression const& _expression, std::unique_ptr<IRLValue> _lvalue);
	void generateLoop(
		Statement const& _body,
		Expression const* _conditionExpression,
		Statement const*  _initExpression = nullptr,
		ExpressionStatement const* _loopExpression = nullptr,
		bool _isDoWhile = false
	);

	static Type const& type(Expression const& _expression);

	std::ostringstream m_code;
	IRGenerationContext& m_context;
	YulUtilFunctions& m_utils;
	std::unique_ptr<IRLValue> m_currentLValue;
};

}
}
