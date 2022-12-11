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

#include <libsolidity/formal/ModelChecker.h>

using namespace std;
using namespace dev;
using namespace langutil;
using namespace dev::solidity;

ModelChecker::ModelChecker(
	ErrorReporter& _errorReporter,
	map<h256, string> const& _smtlib2Responses,
	smt::SMTSolverChoice _enabledSolvers
):
	m_bmc(m_context, _errorReporter, _smtlib2Responses, _enabledSolvers),
	m_chc(m_context, _errorReporter, _smtlib2Responses, _enabledSolvers),
	m_context()
{
}

void ModelChecker::analyze(SourceUnit const& _source)
{
	if (!_source.annotation().experimentalFeatures.count(ExperimentalFeature::SMTChecker))
		return;

	m_chc.analyze(_source);
	m_bmc.analyze(_source, m_chc.safeAssertions());
}

vector<string> ModelChecker::unhandledQueries()
{
	return m_bmc.unhandledQueries() + m_chc.unhandledQueries();
}
