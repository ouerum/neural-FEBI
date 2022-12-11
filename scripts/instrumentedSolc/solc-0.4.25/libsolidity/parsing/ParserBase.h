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
 * Solidity parser shared functionality.
 */

#pragma once

#include <memory>
#include <libsolidity/parsing/Token.h>

namespace dev
{
namespace solidity
{

class ErrorReporter;
class Scanner;

class ParserBase
{
public:
	explicit ParserBase(ErrorReporter& errorReporter): m_errorReporter(errorReporter) {}

	std::shared_ptr<std::string const> const& sourceName() const;

protected:
	/// Utility class that creates an error and throws an exception if the
	/// recursion depth is too deep.
	class RecursionGuard
	{
	public:
		explicit RecursionGuard(ParserBase& _parser): m_parser(_parser)
		{
			m_parser.increaseRecursionDepth();
		}
		~RecursionGuard() { m_parser.decreaseRecursionDepth(); }
	private:
		ParserBase& m_parser;
	};

	/// Start position of the current token
	int position() const;
	/// End position of the current token
	int endPosition() const;

	///@{
	///@name Helper functions
	/// If current token value is not _value, throw exception otherwise advance token.
	void expectToken(Token::Value _value, bool _advance = true);
	Token::Value currentToken() const;
	Token::Value peekNextToken() const;
	std::string currentLiteral() const;
	Token::Value advance();
	///@}

	/// Increases the recursion depth and throws an exception if it is too deep.
	void increaseRecursionDepth();
	void decreaseRecursionDepth();

	/// Creates a @ref ParserError and annotates it with the current position and the
	/// given @a _description.
	void parserError(std::string const& _description);

	/// Creates a @ref ParserError and annotates it with the current position and the
	/// given @a _description. Throws the FatalError.
	void fatalParserError(std::string const& _description);

	std::shared_ptr<Scanner> m_scanner;
	/// The reference to the list of errors and warning to add errors/warnings during parsing
	ErrorReporter& m_errorReporter;
	/// Current recursion depth during parsing.
	size_t m_recursionDepth = 0;
};

}
}
