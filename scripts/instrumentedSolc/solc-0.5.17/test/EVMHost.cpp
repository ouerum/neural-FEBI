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
 * EVM execution host, i.e. component that implements a simulated Ethereum blockchain
 * for testing purposes.
 */

#include <test/EVMHost.h>

#include <test/evmc/loader.h>

#include <libevmasm/GasMeter.h>

#include <libdevcore/Exceptions.h>
#include <libdevcore/Assertions.h>
#include <libdevcore/Keccak256.h>
#include <libdevcore/picosha2.h>

using namespace std;
using namespace dev;
using namespace dev::test;
using namespace evmc::literals;

evmc::VM& EVMHost::getVM(string const& _path)
{
	static evmc::VM theVM;
	if (!theVM && !_path.empty())
	{
		evmc_loader_error_code errorCode = {};
		auto vm = evmc::VM{evmc_load_and_configure(_path.c_str(), &errorCode)};
		if (vm && errorCode == EVMC_LOADER_SUCCESS)
		{
			if (vm.get_capabilities() & EVMC_CAPABILITY_EVM1)
				theVM = std::move(vm);
			else
				cerr << "VM loaded does not support EVM1" << endl;
		}
		else
		{
			cerr << "Error loading VM from " << _path;
			if (char const* errorMsg = evmc_last_error_msg())
				cerr << ":" << endl << errorMsg;
			cerr << endl;
		}
	}
	return theVM;
}

EVMHost::EVMHost(langutil::EVMVersion _evmVersion, evmc::VM& _vm):
	m_vm(_vm),
	m_evmVersion(_evmVersion)
{
	if (!m_vm)
	{
		cerr << "Unable to find evmone library" << endl;
		assertThrow(false, Exception, "");
	}

	if (_evmVersion == langutil::EVMVersion::homestead())
		m_evmRevision = EVMC_HOMESTEAD;
	else if (_evmVersion == langutil::EVMVersion::tangerineWhistle())
		m_evmRevision = EVMC_TANGERINE_WHISTLE;
	else if (_evmVersion == langutil::EVMVersion::spuriousDragon())
		m_evmRevision = EVMC_SPURIOUS_DRAGON;
	else if (_evmVersion == langutil::EVMVersion::byzantium())
		m_evmRevision = EVMC_BYZANTIUM;
	else if (_evmVersion == langutil::EVMVersion::constantinople())
		m_evmRevision = EVMC_CONSTANTINOPLE;
	else if (_evmVersion == langutil::EVMVersion::istanbul())
		m_evmRevision = EVMC_ISTANBUL;
	else if (_evmVersion == langutil::EVMVersion::berlin())
		assertThrow(false, Exception, "Berlin is not supported yet.");
	else //if (_evmVersion == langutil::EVMVersion::petersburg())
		m_evmRevision = EVMC_PETERSBURG;

	// Mark all precompiled contracts as existing. Existing here means to have a balance (as per EIP-161).
	// NOTE: keep this in sync with `EVMHost::call` below.
	//
	// A lot of precompile addresses had a balance before they became valid addresses for precompiles.
	// For example all the precompile addresses allocated in Byzantium had a 1 wei balance sent to them
	// roughly 22 days before the update went live.
	for (unsigned precompiledAddress = 1; precompiledAddress <= 8; precompiledAddress++)
	{
		evmc::address address{};
		address.bytes[19] = precompiledAddress;
		// 1wei
		accounts[address].balance.bytes[31] = 1;
	}

	// TODO: support short literals in EVMC and use them here
	tx_context.block_difficulty = convertToEVMC(u256("200000000"));
	tx_context.block_gas_limit = 20000000;
	tx_context.block_coinbase = 0x7878787878787878787878787878787878787878_address;
	tx_context.tx_gas_price = convertToEVMC(u256("3000000000"));
	tx_context.tx_origin = 0x9292929292929292929292929292929292929292_address;
	// Mainnet according to EIP-155
	tx_context.chain_id = convertToEVMC(u256(1));
}

void EVMHost::selfdestruct(const evmc::address& _addr, const evmc::address& _beneficiary) noexcept
{
	// TODO actual selfdestruct is even more complicated.
	evmc::uint256be balance = accounts[_addr].balance;
	accounts.erase(_addr);
	accounts[_beneficiary].balance = balance;
}

evmc::result EVMHost::call(evmc_message const& _message) noexcept
{
	if (_message.destination == 0x0000000000000000000000000000000000000001_address)
		return precompileECRecover(_message);
	else if (_message.destination == 0x0000000000000000000000000000000000000002_address)
		return precompileSha256(_message);
	else if (_message.destination == 0x0000000000000000000000000000000000000003_address)
		return precompileRipeMD160(_message);
	else if (_message.destination == 0x0000000000000000000000000000000000000004_address)
		return precompileIdentity(_message);
	else if (_message.destination == 0x0000000000000000000000000000000000000005_address && m_evmVersion >= langutil::EVMVersion::byzantium())
		return precompileModExp(_message);
	else if (_message.destination == 0x0000000000000000000000000000000000000006_address && m_evmVersion >= langutil::EVMVersion::byzantium())
		return precompileALTBN128G1Add(_message);
	else if (_message.destination == 0x0000000000000000000000000000000000000007_address && m_evmVersion >= langutil::EVMVersion::byzantium())
		return precompileALTBN128G1Mul(_message);
	else if (_message.destination == 0x0000000000000000000000000000000000000008_address && m_evmVersion >= langutil::EVMVersion::byzantium())
		return precompileALTBN128PairingProduct(_message);

	auto const stateBackup = accounts;

	u256 value{convertFromEVMC(_message.value)};
	auto& sender = accounts[_message.sender];

	evmc::bytes code;

	evmc_message message = _message;
	if (message.depth == 0)
	{
		message.gas -= message.kind == EVMC_CREATE ? eth::GasCosts::txCreateGas : eth::GasCosts::txGas;
		for (size_t i = 0; i < message.input_size; ++i)
			message.gas -= message.input_data[i] == 0 ? eth::GasCosts::txDataZeroGas : eth::GasCosts::txDataNonZeroGas(m_evmVersion);
		if (message.gas < 0)
		{
			evmc::result result({});
			result.status_code = EVMC_OUT_OF_GAS;
			accounts = stateBackup;
			return result;
		}
	}

	if (message.kind == EVMC_CREATE)
	{
		// TODO this is not the right formula
		// TODO is the nonce incremented on failure, too?
		Address createAddress(keccak256(
			bytes(begin(message.sender.bytes), end(message.sender.bytes)) +
			asBytes(to_string(sender.nonce++))
		));
		message.destination = convertToEVMC(createAddress);
		code = evmc::bytes(message.input_data, message.input_data + message.input_size);
	}
	else if (message.kind == EVMC_DELEGATECALL)
	{
		code = accounts[message.destination].code;
		message.destination = m_currentAddress;
	}
	else if (message.kind == EVMC_CALLCODE)
	{
		code = accounts[message.destination].code;
		message.destination = m_currentAddress;
	}
	else
		code = accounts[message.destination].code;
	//TODO CREATE2

	auto& destination = accounts[message.destination];

	if (value != 0 && message.kind != EVMC_DELEGATECALL && message.kind != EVMC_CALLCODE)
	{
		sender.balance = convertToEVMC(u256(convertFromEVMC(sender.balance)) - value);
		destination.balance = convertToEVMC(u256(convertFromEVMC(destination.balance)) + value);
	}

	evmc::address currentAddress = m_currentAddress;
	m_currentAddress = message.destination;
	evmc::result result = m_vm.execute(*this, m_evmRevision, message, code.data(), code.size());
	m_currentAddress = currentAddress;

	if (message.kind == EVMC_CREATE)
	{
		result.gas_left -= eth::GasCosts::createDataGas * result.output_size;
		if (result.gas_left < 0)
		{
			result.gas_left = 0;
			result.status_code = EVMC_OUT_OF_GAS;
			// TODO clear some fields?
		}
		else
		{
			result.create_address = message.destination;
			destination.code = evmc::bytes(result.output_data, result.output_data + result.output_size);
			destination.codehash = convertToEVMC(keccak256({result.output_data, result.output_size}));
		}
	}

	if (result.status_code != EVMC_SUCCESS)
		accounts = stateBackup;

	return result;
}

evmc::bytes32 EVMHost::get_block_hash(int64_t _number) const noexcept
{
	return convertToEVMC(u256("0x3737373737373737373737373737373737373737373737373737373737373737") + _number);
}

Address EVMHost::convertFromEVMC(evmc::address const& _addr)
{
	return Address(bytes(begin(_addr.bytes), end(_addr.bytes)));
}

evmc::address EVMHost::convertToEVMC(Address const& _addr)
{
	evmc::address a;
	for (size_t i = 0; i < 20; ++i)
		a.bytes[i] = _addr[i];
	return a;
}

h256 EVMHost::convertFromEVMC(evmc::bytes32 const& _data)
{
	return h256(bytes(begin(_data.bytes), end(_data.bytes)));
}

evmc::bytes32 EVMHost::convertToEVMC(h256 const& _data)
{
	evmc::bytes32 d;
	for (size_t i = 0; i < 32; ++i)
		d.bytes[i] = _data[i];
	return d;
}

evmc::result EVMHost::precompileECRecover(evmc_message const& _message) noexcept
{
	// NOTE this is a partial implementation for some inputs.
	static map<bytes, bytes> const inputOutput{
		{
			fromHex(
				"18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
				"000000000000000000000000000000000000000000000000000000000000001c"
				"73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
				"eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549"
			),
			fromHex("000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b")
		},
		{
			fromHex(
				"47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
				"000000000000000000000000000000000000000000000000000000000000001c"
				"debaaa0cddb321b2dcaaf846d39605de7b97e77ba6106587855b9106cb104215"
				"61a22d94fa8b8a687ff9c911c844d1c016d1a685a9166858f9c7c1bc85128aca"
			),
			fromHex("0000000000000000000000008743523d96a1b2cbe0c6909653a56da18ed484af")
		}
	};
	evmc::result result = precompileGeneric(_message, inputOutput);
	result.status_code = EVMC_SUCCESS;
	result.gas_left = _message.gas;
	return result;
}

evmc::result EVMHost::precompileSha256(evmc_message const& _message) noexcept
{
	// static data so that we do not need a release routine...
	bytes static hash;
	hash = picosha2::hash256(bytes(
		_message.input_data,
		_message.input_data + _message.input_size
	));

	evmc::result result({});
	result.gas_left = _message.gas;
	result.output_data = hash.data();
	result.output_size = hash.size();
	return result;
}

evmc::result EVMHost::precompileRipeMD160(evmc_message const& _message) noexcept
{
	// NOTE this is a partial implementation for some inputs.
	static map<bytes, bytes> const inputOutput{
		{
			bytes{},
			fromHex("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31")
		},
		{
			fromHex("0000000000000000000000000000000000000000000000000000000000000004"),
			fromHex("0000000000000000000000001b0f3c404d12075c68c938f9f60ebea4f74941a0")
		},
		{
			fromHex("0000000000000000000000000000000000000000000000000000000000000005"),
			fromHex("000000000000000000000000ee54aa84fc32d8fed5a5fe160442ae84626829d9")
		},
		{
			fromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
			fromHex("0000000000000000000000001cf4e77f5966e13e109703cd8a0df7ceda7f3dc3")
		},
		{
			fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("000000000000000000000000f93175303eba2a7b372174fc9330237f5ad202fc")
		},
		{
			fromHex(
				"0800000000000000000000000000000000000000000000000000000000000000"
				"0401000000000000000000000000000000000000000000000000000000000000"
				"0000000400000000000000000000000000000000000000000000000000000000"
				"00000100"
			),
			fromHex("000000000000000000000000f93175303eba2a7b372174fc9330237f5ad202fc")
		},
		{
			fromHex(
				"0800000000000000000000000000000000000000000000000000000000000000"
				"0501000000000000000000000000000000000000000000000000000000000000"
				"0000000500000000000000000000000000000000000000000000000000000000"
				"00000100"
			),
			fromHex("0000000000000000000000004f4fc112e2bfbe0d38f896a46629e08e2fcfad5")
		},
		{
			fromHex(
				"08ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				"ff010000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				"ffffffff00000000000000000000000000000000000000000000000000000000"
				"00000100"
			),
			fromHex("000000000000000000000000c0a2e4b1f3ff766a9a0089e7a410391730872495")
		},
		{
			fromHex(
				"6162636465666768696a6b6c6d6e6f707172737475767778797a414243444546"
				"4748494a4b4c4d4e4f505152535455565758595a303132333435363738393f21"
			),
			fromHex("00000000000000000000000036c6b90a49e17d4c1e1b0e634ec74124d9b207da")
		},
		{
			fromHex("6162636465666768696a6b6c6d6e6f707172737475767778797a414243444546"),
			fromHex("000000000000000000000000ac5ab22e07b0fb80c69b6207902f725e2507e546")
		}
	};
	return precompileGeneric(_message, inputOutput);
}

evmc::result EVMHost::precompileIdentity(evmc_message const& _message) noexcept
{
	// static data so that we do not need a release routine...
	bytes static data;
	data = bytes(_message.input_data, _message.input_data + _message.input_size);
	evmc::result result({});
	result.gas_left = _message.gas;
	result.output_data = data.data();
	result.output_size = data.size();
	return result;
}

evmc::result EVMHost::precompileModExp(evmc_message const&) noexcept
{
	// TODO implement
	evmc::result result({});
	result.status_code = EVMC_FAILURE;
	return result;
}

evmc::result EVMHost::precompileALTBN128G1Add(evmc_message const& _message) noexcept
{
	// NOTE this is a partial implementation for some inputs.

	static map<bytes, bytes> const inputOutput{
		{
			fromHex(
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"1385281136ff5b2c326807ff0a824b6ca4f21fcc7c8764e9801bc4ad497d5012"
				"02254594be8473dcf018a2aa66ea301e38fc865823acf75a9901721d1fc6bf4c"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"1385281136ff5b2c326807ff0a824b6ca4f21fcc7c8764e9801bc4ad497d5012"
				"02254594be8473dcf018a2aa66ea301e38fc865823acf75a9901721d1fc6bf4c"
			)
		},
		{
			fromHex(
				"0000000000000000000000000000000000000000000000000000000000000001"
				"0000000000000000000000000000000000000000000000000000000000000002"
				"0000000000000000000000000000000000000000000000000000000000000001"
				"0000000000000000000000000000000000000000000000000000000000000002"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3"
				"15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4"
			)
		},
		{
			fromHex(
				"0000000000000000000000000000000000000000000000000000000000000001"
				"0000000000000000000000000000000000000000000000000000000000000002"
				"0000000000000000000000000000000000000000000000000000000000000001"
				"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			)
		},
		{
			fromHex(
				"10b4876441e14a6be92a7fe66550848c01c676a12ac31d7cc13b21f49c4307c8"
				"09f5528bdb0ef9354837a0f4b4c9da973bd5b805d359976f719ab0b74e0a7368"
				"28d3c57516712e7843a5b3cfa7d7274a037943f5bd57c227620ad207728e4283"
				"2795fa9df21d4b8b329a45bae120f1fd9df9049ecacaa9dd1eca18bc6a55cd2f"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"16aed5ed486df6b2fb38015ded41400009ed4f34bef65b87b1f90f47052f8d94"
				"16dabf21b3f25b9665269d98dc17b1da6118251dc0b403ae50e96dfe91239375"
			)
		},
		{
			fromHex(
				"1385281136ff5b2c326807ff0a824b6ca4f21fcc7c8764e9801bc4ad497d5012"
				"02254594be8473dcf018a2aa66ea301e38fc865823acf75a9901721d1fc6bf4c"
				"1644e84fef7b7fdc98254f0654580173307a3bc44db990581e7ab55a22446dcf"
				"28c2916b7e875692b195831945805438fcd30d2693d8a80cf8c88ec6ef4c315d"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"1e018816fc9bbd91313301ae9c254bb7d64d6cd54f3b49b92925e43e256b5faa"
				"1d1f2259c715327bedb42c095af6c0267e4e1be836b4e04b3f0502552f93cca9"
			)
		},
		{
			fromHex(
				"16aed5ed486df6b2fb38015ded41400009ed4f34bef65b87b1f90f47052f8d94"
				"16dabf21b3f25b9665269d98dc17b1da6118251dc0b403ae50e96dfe91239375"
				"25ff95a3abccf32adc6a4c3c8caddca67723d8ada802e9b9f612e3ddb40b2005"
				"0d82b09bb4ec927bbf182bdc402790429322b7e2f285f2aad8ea135cbf7143d8"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"29d160febeef9770d47a32ee3b763850eb0594844fa57dd31b8ed02c78fdb797"
				"2c7cdf62c2498486fd52646e577a06723ce97737b3c958262d78c4a413661e8a"
			),
		},
		{
			fromHex(
				"18014701594179c6b9ccae848e3d15c1f76f8a68b8092578296520e46c9bae0c"
				"1b5ed0e9e8f3ff35589ea81a45cf63887d4a92c099a3be1d97b26f0db96323dd"
				"16a1d378d1a98cf5383cdc512011234287ca43b6a078d1842d5c58c5b1f475cc"
				"1309377a7026d08ca1529eab74381a7e0d3a4b79d80bacec207cd52fc8e3769c"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"2583ed10e418133e44619c336f1be5ddae9e20d634a7683d9661401c750d7df4"
				"0185fbba22de9e698262925665735dbc4d6e8288bc3fc39fae10ca58e16e77f7"
			)
		},
		{
			fromHex(
				"1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f59"
				"3034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41"
				"0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2"
				"16da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"1496064626ba8bffeb7805f0d16143a65649bb0850333ea512c03fcdaf31e254"
				"07b4f210ab542533f1ee5633ae4406cd16c63494b537ce3f1cf4afff6f76a48f"
			),
		},
		{
			fromHex(
				"1e018816fc9bbd91313301ae9c254bb7d64d6cd54f3b49b92925e43e256b5faa"
				"1d1f2259c715327bedb42c095af6c0267e4e1be836b4e04b3f0502552f93cca9"
				"2364294faf6b89fedeede9986aa777c4f6c2f5c4a4559ee93dfec9b7b94ef80b"
				"05aeae62655ea23865ae6661ae371a55c12098703d0f2301f4223e708c92efc6"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"2801b21090cbc48409e352647f3857134d373f81741f9d5e3d432f336d76f517"
				"13cf106acf943c2a331de21c7d5e3351354e7412f2dba2918483a6593a6828d4"
			)
		},
		{
			fromHex(
				"2583ed10e418133e44619c336f1be5ddae9e20d634a7683d9661401c750d7df4"
				"0185fbba22de9e698262925665735dbc4d6e8288bc3fc39fae10ca58e16e77f7"
				"258f1faa356e470cca19c928afa5ceed6215c756912af5725b8db5777cc8f3b6"
				"175ced8a58d0c132c2b95ba14c16dde93e7f7789214116ff69da6f44daa966e6"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"10b4876441e14a6be92a7fe66550848c01c676a12ac31d7cc13b21f49c4307c8"
				"09f5528bdb0ef9354837a0f4b4c9da973bd5b805d359976f719ab0b74e0a7368"
			)
		},
		{
			fromHex(
				"26dcfbc2e0bc9d82efb4acd73cb3e99730e27e10177fcfb78b6399a4bfcdf391"
				"27c440dbd5053253a3a692f9bf89b9b6e9612127cf97db1e11ffa9679acc933b"
				"1496064626ba8bffeb7805f0d16143a65649bb0850333ea512c03fcdaf31e254"
				"07b4f210ab542533f1ee5633ae4406cd16c63494b537ce3f1cf4afff6f76a48f"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"186bac5188a98c45e6016873d107f5cd131f3a3e339d0375e58bd6219347b008"
				"1e396bc242de0214898b0f68035f53ad5a6f96c6c8390ac56ed6ec9561d23159"
			)
		},
		{
			fromHex(
				"26dcfbc2e0bc9d82efb4acd73cb3e99730e27e10177fcfb78b6399a4bfcdf391"
				"27c440dbd5053253a3a692f9bf89b9b6e9612127cf97db1e11ffa9679acc933b"
				"1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f59"
				"3034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"20a754d2071d4d53903e3b31a7e98ad6882d58aec240ef981fdf0a9d22c5926a"
				"29c853fcea789887315916bbeb89ca37edb355b4f980c9a12a94f30deeed3021"
			)
		},
		{
			fromHex(
				"27231d5cdd0011259ff75678cf5a8f7840c22cb71d52b25e21e071205e8d9bc4"
				"26dd3d225c9a71476db0cf834232eba84020f3073c6d20c519963e0b98f235e1"
				"2174f0221490cd9c15b0387f3251ec3d49517a51c37a8076eac12afb4a95a707"
				"1d1c3fcd3161e2a417b4df0955f02db1fffa9005210fb30c5aa3755307e9d1f5"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"18014701594179c6b9ccae848e3d15c1f76f8a68b8092578296520e46c9bae0c"
				"1b5ed0e9e8f3ff35589ea81a45cf63887d4a92c099a3be1d97b26f0db96323dd"
			),
		},
		{
			fromHex(
				"2801b21090cbc48409e352647f3857134d373f81741f9d5e3d432f336d76f517"
				"13cf106acf943c2a331de21c7d5e3351354e7412f2dba2918483a6593a6828d4"
				"2a49621e12910cd90f3e731083d454255bf1c533d6e15b8699156778d0f27f5d"
				"2590ee31824548d159aa2d22296bf149d564c0872f41b89b7dc5c6e6e3cd1c4d"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"27231d5cdd0011259ff75678cf5a8f7840c22cb71d52b25e21e071205e8d9bc4"
				"26dd3d225c9a71476db0cf834232eba84020f3073c6d20c519963e0b98f235e1"
			)
		},
		{
			fromHex(
				"29d160febeef9770d47a32ee3b763850eb0594844fa57dd31b8ed02c78fdb797"
				"2c7cdf62c2498486fd52646e577a06723ce97737b3c958262d78c4a413661e8a"
				"0aee46a7ea6e80a3675026dfa84019deee2a2dedb1bbe11d7fe124cb3efb4b5a"
				"044747b6e9176e13ede3a4dfd0d33ccca6321b9acd23bf3683a60adc0366ebaf"
				"0000000000000000000000000000000000000000000000000000000000000000"
				"0000000000000000000000000000000000000000000000000000000000000000"
			),
			fromHex(
				"26dcfbc2e0bc9d82efb4acd73cb3e99730e27e10177fcfb78b6399a4bfcdf391"
				"27c440dbd5053253a3a692f9bf89b9b6e9612127cf97db1e11ffa9679acc933b"
			)
		}
	};
	return precompileGeneric(_message, inputOutput);
}

evmc::result EVMHost::precompileALTBN128G1Mul(evmc_message const& _message) noexcept
{
	// NOTE this is a partial implementation for some inputs.
	static map<bytes, bytes> const inputOutput{
		{
			fromHex("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd315ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4")
		},
		{
			fromHex("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c")
		},
		{
			fromHex("09b54f111d3b2d1b2fe1ae9669b3db3d7bf93b70f00647e65c849275de6dc7fe18b2e77c63a3e400d6d1f1fbc6e1a1167bbca603d34d03edea231eb0ab7b14b4030f7b0c405c888aff922307ea2cd1c70f64664bab76899500341f4260a209290000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("16a1d378d1a98cf5383cdc512011234287ca43b6a078d1842d5c58c5b1f475cc1309377a7026d08ca1529eab74381a7e0d3a4b79d80bacec207cd52fc8e3769c")
		},
		{
			fromHex("0a6de0e2240aa253f46ce0da883b61976e3588146e01c9d8976548c145fe6e4a04fbaa3a4aed4bb77f30ebb07a3ec1c7d77a7f2edd75636babfeff97b1ea686e1551dcd4965285ef049512d2d30cbfc1a91acd5baad4a6e19e22e93176197f170000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("28d3c57516712e7843a5b3cfa7d7274a037943f5bd57c227620ad207728e42832795fa9df21d4b8b329a45bae120f1fd9df9049ecacaa9dd1eca18bc6a55cd2f")
		},
		{
			fromHex("0c54b42137b67cc268cbb53ac62b00ecead23984092b494a88befe58445a244a18e3723d37fae9262d58b548a0575f59d9c3266db7afb4d5739555837f6b8b3e0c692b41f1acc961f6ea83bae2c3a1a55c54f766c63ba76989f52c149c17b5e70000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("258f1faa356e470cca19c928afa5ceed6215c756912af5725b8db5777cc8f3b6175ced8a58d0c132c2b95ba14c16dde93e7f7789214116ff69da6f44daa966e6")
		},
		{
			fromHex("0f103f14a584d4203c27c26155b2c955f8dfa816980b24ba824e1972d6486a5d0c4165133b9f5be17c804203af781bcf168da7386620479f9b885ecbcd27b17b0ea71d0abb524cac7cfff5323e1d0b14ab705842426c978f96753ccce258ed930000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("2a49621e12910cd90f3e731083d454255bf1c533d6e15b8699156778d0f27f5d2590ee31824548d159aa2d22296bf149d564c0872f41b89b7dc5c6e6e3cd1c4d")
		},
		{
			fromHex("111e2e2a5f8828f80ddad08f9f74db56dac1cc16c1cb278036f79a84cf7a116f1d7d62e192b219b9808faa906c5ced871788f6339e8d91b83ac1343e20a16b3000000000000000000000000000000000000000e40800000000000000008cdcbc0000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("25ff95a3abccf32adc6a4c3c8caddca67723d8ada802e9b9f612e3ddb40b20050d82b09bb4ec927bbf182bdc402790429322b7e2f285f2aad8ea135cbf7143d8")
		},
		{
			fromHex("17d5d09b4146424bff7e6fb01487c477bbfcd0cdbbc92d5d6457aae0b6717cc502b5636903efbf46db9235bbe74045d21c138897fda32e079040db1a16c1a7a11887420878c0c8e37605291c626585eabbec8d8b97a848fe8d58a37b004583510000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("2364294faf6b89fedeede9986aa777c4f6c2f5c4a4559ee93dfec9b7b94ef80b05aeae62655ea23865ae6661ae371a55c12098703d0f2301f4223e708c92efc6")
		},
		{
			fromHex("1c36e713d4d54e3a9644dffca1fc524be4868f66572516025a61ca542539d43f042dcc4525b82dfb242b09cb21909d5c22643dcdbe98c4d082cc2877e96b24db016086cc934d5cab679c6991a4efcedbab26d7e4fb23b6a1ad4e6b5c2fb59ce50000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("1644e84fef7b7fdc98254f0654580173307a3bc44db990581e7ab55a22446dcf28c2916b7e875692b195831945805438fcd30d2693d8a80cf8c88ec6ef4c315d")
		},
		{
			fromHex("1e39e9f0f91fa7ff8047ffd90de08785777fe61c0e3434e728fce4cf35047ddc2e0b64d75ebfa86d7f8f8e08abbe2e7ae6e0a1c0b34d028f19fa56e9450527cb1eec35a0e955cad4bee5846ae0f1d0b742d8636b278450c534e38e06a60509f90000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("1385281136ff5b2c326807ff0a824b6ca4f21fcc7c8764e9801bc4ad497d501202254594be8473dcf018a2aa66ea301e38fc865823acf75a9901721d1fc6bf4c")
		},
		{
			fromHex("232063b584fb76c8d07995bee3a38fa7565405f3549c6a918ddaa90ab971e7f82ac9b135a81d96425c92d02296322ad56ffb16299633233e4880f95aafa7fda70689c3dc4311426ee11707866b2cbdf9751dacd07245bf99d2113d3f5a8cac470000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("2174f0221490cd9c15b0387f3251ec3d49517a51c37a8076eac12afb4a95a7071d1c3fcd3161e2a417b4df0955f02db1fffa9005210fb30c5aa3755307e9d1f5")
		}
	};
	return precompileGeneric(_message, inputOutput);
}

evmc::result EVMHost::precompileALTBN128PairingProduct(evmc_message const& _message) noexcept
{
	// This is a partial implementation - it always returns "success"
	bytes static data = fromHex("0000000000000000000000000000000000000000000000000000000000000001");
	return resultWithGas(_message, data);
}

evmc::result EVMHost::precompileGeneric(
	evmc_message const& _message,
	map<bytes, bytes> const& _inOut) noexcept
{
	bytes input(_message.input_data, _message.input_data + _message.input_size);
	if (_inOut.count(input))
		return resultWithGas(_message, _inOut.at(input));
	else
	{
		evmc::result result({});
		result.status_code = EVMC_FAILURE;
		return result;
	}
}

evmc::result EVMHost::resultWithGas(
	evmc_message const& _message,
	bytes const& _data
) noexcept
{
	evmc::result result({});
	result.status_code = EVMC_SUCCESS;
	result.gas_left = _message.gas;
	result.output_data = _data.data();
	result.output_size = _data.size();
	return result;
}
