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

#pragma once

#include <libdevcore/Exceptions.h>
#include <liblangutil/EVMVersion.h>

#include <boost/filesystem/path.hpp>
#include <boost/program_options.hpp>
#include <boost/noncopyable.hpp>

namespace dev
{

namespace test
{

#ifdef _WIN32
static constexpr auto evmoneFilename = "evmone.dll";
static constexpr auto evmoneDownloadLink = "https://github.com/ethereum/evmone/releases/download/v0.3.0/evmone-0.3.0-windows-amd64.zip";
#elif defined(__APPLE__)
static constexpr auto evmoneFilename = "libevmone.dylib";
static constexpr auto evmoneDownloadLink = "https://github.com/ethereum/evmone/releases/download/v0.3.0/evmone-0.3.0-darwin-x86_64.tar.gz";
#else
static constexpr auto evmoneFilename = "libevmone.so";
static constexpr auto evmoneDownloadLink = "https://github.com/ethereum/evmone/releases/download/v0.3.0/evmone-0.3.0-linux-x86_64.tar.gz";
#endif


struct ConfigException : public Exception {};

struct CommonOptions: boost::noncopyable
{
	boost::filesystem::path evmonePath;
	boost::filesystem::path testPath;
	bool optimize = false;
	bool optimizeYul = false;
	bool disableSMT = false;

	langutil::EVMVersion evmVersion() const;

	virtual bool parse(int argc, char const* const* argv);
	// Throws a ConfigException on error
	virtual void validate() const;

protected:
	CommonOptions(std::string caption = "");

	boost::program_options::options_description options;

private:
	std::string evmVersionString;
};

}
}
