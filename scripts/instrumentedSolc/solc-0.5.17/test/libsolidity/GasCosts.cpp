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
 * Tests that check that the cost of certain operations stay within range.
 */

#include <test/libsolidity/SolidityExecutionFramework.h>
#include <liblangutil/EVMVersion.h>
#include <libdevcore/SwarmHash.h>
#include <libevmasm/GasMeter.h>

#include <cmath>

using namespace std;
using namespace langutil;
using namespace dev::eth;
using namespace dev::solidity;
using namespace dev::test;

namespace dev
{
namespace solidity
{
namespace test
{

#define CHECK_DEPLOY_GAS(_gasNoOpt, _gasOpt, _evmVersion) \
	do \
	{ \
		u256 bzzr1Cost = GasMeter::dataGas(dev::bzzr1Hash(m_compiler.metadata(m_compiler.lastContractName())).asBytes(), true, _evmVersion); \
		u256 gasOpt{_gasOpt}; \
		u256 gasNoOpt{_gasNoOpt}; \
		u256 gas = m_optimiserSettings == OptimiserSettings::minimal() ? gasNoOpt : gasOpt; \
		BOOST_CHECK_MESSAGE( \
			m_gasUsed >= bzzr1Cost, \
			"Gas used: " + \
			m_gasUsed.str() + \
			" is less than the data cost for the bzzr1 hash: " + \
			u256(bzzr1Cost).str() \
		); \
		u256 gasUsed = m_gasUsed - bzzr1Cost; \
		BOOST_CHECK_MESSAGE( \
			gas == gasUsed, \
			"Gas used: " + \
			gasUsed.str() + \
			" - expected: " + \
			gas.str() \
		); \
	} while(0)

#define CHECK_GAS(_gasNoOpt, _gasOpt, _tolerance) \
	do \
	{ \
		u256 gasOpt{_gasOpt}; \
		u256 gasNoOpt{_gasNoOpt}; \
		u256 tolerance{_tolerance}; \
		u256 gas = m_optimiserSettings == OptimiserSettings::minimal() ? gasNoOpt : gasOpt; \
		u256 diff = gas < m_gasUsed ? m_gasUsed - gas : gas - m_gasUsed; \
		BOOST_CHECK_MESSAGE( \
			diff <= tolerance, \
			"Gas used: " + \
			m_gasUsed.str() + \
			" - expected: " + \
			gas.str() + \
			" (tolerance: " + \
			tolerance.str() + \
			")" \
		); \
	} while(0)

BOOST_FIXTURE_TEST_SUITE(GasCostTests, SolidityExecutionFramework)

BOOST_AUTO_TEST_CASE(string_storage)
{
	char const* sourceCode = R"(
		contract C {
			function f() pure public {
				require(false, "Not Authorized. This function can only be called by the custodian or owner of this contract");
			}
		}
	)";
	m_compiler.overwriteReleaseFlag(true);
	compileAndRun(sourceCode);

	auto evmVersion = dev::test::Options::get().evmVersion();

	if (evmVersion <= EVMVersion::byzantium())
		CHECK_DEPLOY_GAS(134071, 130763, evmVersion);
	// This is only correct on >=Constantinople.
	else if (Options::get().useABIEncoderV2)
	{
		if (Options::get().optimizeYul)
		{
			// Costs with 0 are cases which cannot be triggered in tests.
			if (evmVersion < EVMVersion::istanbul())
				CHECK_DEPLOY_GAS(0, 127653, evmVersion);
			else
				CHECK_DEPLOY_GAS(0, 113821, evmVersion);
		}
		else
		{
			if (evmVersion < EVMVersion::istanbul())
				CHECK_DEPLOY_GAS(0, 135371, evmVersion);
			else
				CHECK_DEPLOY_GAS(0, 120083, evmVersion);
		}
	}
	else if (evmVersion < EVMVersion::istanbul())
		CHECK_DEPLOY_GAS(126861, 119591, evmVersion);
	else
		CHECK_DEPLOY_GAS(114173, 107163, evmVersion);

	if (evmVersion >= EVMVersion::byzantium())
	{
		callContractFunction("f()");
		if (evmVersion == EVMVersion::byzantium())
			CHECK_GAS(21551, 21526, 20);
		// This is only correct on >=Constantinople.
		else if (Options::get().useABIEncoderV2)
		{
			if (Options::get().optimizeYul)
			{
				if (evmVersion < EVMVersion::istanbul())
					CHECK_GAS(0, 21567, 20);
				else
					CHECK_GAS(0, 21351, 20);
			}
			else
			{
				if (evmVersion < EVMVersion::istanbul())
					CHECK_GAS(0, 21635, 20);
				else
					CHECK_GAS(0, 21431, 20);
			}
		}
		else if (evmVersion < EVMVersion::istanbul())
			CHECK_GAS(21546, 21526, 20);
		else
			CHECK_GAS(21332, 21322, 20);
	}
}

BOOST_AUTO_TEST_CASE(single_callvaluecheck)
{
	string sourceCode = R"(
		// All functions nonpayable, we can check callvalue at the beginning
		contract Nonpayable {
			address a;
			function f(address b) public {
				a = b;
			}
			function f1(address b) public pure returns (uint c) {
				return uint(b) + 2;
			}
			function f2(address b) public pure returns (uint) {
				return uint(b) + 8;
			}
			function f3(address, uint c) pure public returns (uint) {
				return c - 5;
			}
		}
		// At least on payable function, we cannot do the optimization.
		contract Payable {
			address a;
			function f(address b) public {
				a = b;
			}
			function f1(address b) public pure returns (uint c) {
				return uint(b) + 2;
			}
			function f2(address b) public pure returns (uint) {
				return uint(b) + 8;
			}
			function f3(address, uint c) payable public returns (uint) {
				return c - 5;
			}
		}
	)";
	compileAndRun(sourceCode);
	size_t bytecodeSizeNonpayable = m_compiler.object("Nonpayable").bytecode.size();
	size_t bytecodeSizePayable = m_compiler.object("Payable").bytecode.size();

	BOOST_CHECK_EQUAL(bytecodeSizePayable - bytecodeSizeNonpayable, 26);
}

BOOST_AUTO_TEST_SUITE_END()

}
}
}
