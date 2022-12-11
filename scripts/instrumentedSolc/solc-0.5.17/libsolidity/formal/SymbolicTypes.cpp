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

#include <libsolidity/formal/SymbolicTypes.h>

#include <libsolidity/ast/TypeProvider.h>
#include <libsolidity/ast/Types.h>
#include <libdevcore/CommonData.h>
#include <memory>

using namespace std;

namespace dev
{
namespace solidity
{
namespace smt
{

SortPointer smtSort(solidity::Type const& _type)
{
	switch (smtKind(_type.category()))
	{
	case Kind::Int:
		return make_shared<Sort>(Kind::Int);
	case Kind::Bool:
		return make_shared<Sort>(Kind::Bool);
	case Kind::Function:
	{
		auto fType = dynamic_cast<solidity::FunctionType const*>(&_type);
		solAssert(fType, "");
		vector<SortPointer> parameterSorts = smtSort(fType->parameterTypes());
		auto returnTypes = fType->returnParameterTypes();
		SortPointer returnSort;
		// TODO change this when we support tuples.
		if (returnTypes.size() == 0)
			// We cannot declare functions without a return sort, so we use the smallest.
			returnSort = make_shared<Sort>(Kind::Bool);
		else if (returnTypes.size() > 1)
			// Abstract sort.
			returnSort = make_shared<Sort>(Kind::Int);
		else
			returnSort = smtSort(*returnTypes.front());
		return make_shared<FunctionSort>(parameterSorts, returnSort);
	}
	case Kind::Array:
	{
		if (isMapping(_type.category()))
		{
			auto mapType = dynamic_cast<solidity::MappingType const*>(&_type);
			solAssert(mapType, "");
			return make_shared<ArraySort>(smtSortAbstractFunction(*mapType->keyType()), smtSortAbstractFunction(*mapType->valueType()));
		}
		else if (isStringLiteral(_type.category()))
		{
			auto stringLitType = dynamic_cast<solidity::StringLiteralType const*>(&_type);
			solAssert(stringLitType, "");
			auto intSort = make_shared<Sort>(Kind::Int);
			return make_shared<ArraySort>(intSort, intSort);
		}
		else
		{
			solAssert(isArray(_type.category()), "");
			auto arrayType = dynamic_cast<solidity::ArrayType const*>(&_type);
			solAssert(arrayType, "");
			return make_shared<ArraySort>(make_shared<Sort>(Kind::Int), smtSortAbstractFunction(*arrayType->baseType()));
		}
	}
	default:
		// Abstract case.
		return make_shared<Sort>(Kind::Int);
	}
}

vector<SortPointer> smtSort(vector<solidity::TypePointer> const& _types)
{
	vector<SortPointer> sorts;
	for (auto const& type: _types)
		sorts.push_back(smtSort(*type));
	return sorts;
}

SortPointer smtSortAbstractFunction(solidity::Type const& _type)
{
	if (isFunction(_type.category()))
		return make_shared<Sort>(Kind::Int);
	return smtSort(_type);
}

Kind smtKind(solidity::Type::Category _category)
{
	if (isNumber(_category))
		return Kind::Int;
	else if (isBool(_category))
		return Kind::Bool;
	else if (isFunction(_category))
		return Kind::Function;
	else if (isMapping(_category) || isArray(_category))
		return Kind::Array;
	// Abstract case.
	return Kind::Int;
}

bool isSupportedType(solidity::Type::Category _category)
{
	return isNumber(_category) ||
		isBool(_category) ||
		isMapping(_category) ||
		isArray(_category) ||
		isTuple(_category);
}

bool isSupportedTypeDeclaration(solidity::Type::Category _category)
{
	return isSupportedType(_category) ||
		isFunction(_category);
}

pair<bool, shared_ptr<SymbolicVariable>> newSymbolicVariable(
	solidity::Type const& _type,
	std::string const& _uniqueName,
	EncodingContext& _context
)
{
	bool abstract = false;
	shared_ptr<SymbolicVariable> var;
	solidity::TypePointer type = &_type;
	if (!isSupportedTypeDeclaration(_type))
	{
		abstract = true;
		var = make_shared<SymbolicIntVariable>(solidity::TypeProvider::uint256(), type, _uniqueName, _context);
	}
	else if (isBool(_type.category()))
		var = make_shared<SymbolicBoolVariable>(type, _uniqueName, _context);
	else if (isFunction(_type.category()))
	{
		auto const& fType = dynamic_cast<FunctionType const*>(type);
		auto const& paramsIn = fType->parameterTypes();
		auto const& paramsOut = fType->returnParameterTypes();
		auto findFunctionParam = [&](auto&& params) {
			return find_if(
				begin(params),
				end(params),
				[&](TypePointer _paramType) { return _paramType->category() == solidity::Type::Category::Function; }
			);
		};
		if (
			findFunctionParam(paramsIn) != end(paramsIn) ||
			findFunctionParam(paramsOut) != end(paramsOut)
		)
		{
			abstract = true;
			var = make_shared<SymbolicIntVariable>(TypeProvider::uint256(), type, _uniqueName, _context);
		}
		else
			var = make_shared<SymbolicFunctionVariable>(type, _uniqueName, _context);
	}
	else if (isInteger(_type.category()))
		var = make_shared<SymbolicIntVariable>(type, type, _uniqueName, _context);
	else if (isFixedBytes(_type.category()))
	{
		auto fixedBytesType = dynamic_cast<solidity::FixedBytesType const*>(type);
		solAssert(fixedBytesType, "");
		var = make_shared<SymbolicFixedBytesVariable>(type, fixedBytesType->numBytes(), _uniqueName, _context);
	}
	else if (isAddress(_type.category()) || isContract(_type.category()))
		var = make_shared<SymbolicAddressVariable>(_uniqueName, _context);
	else if (isEnum(_type.category()))
		var = make_shared<SymbolicEnumVariable>(type, _uniqueName, _context);
	else if (isRational(_type.category()))
	{
		auto rational = dynamic_cast<solidity::RationalNumberType const*>(&_type);
		solAssert(rational, "");
		if (rational->isFractional())
			var = make_shared<SymbolicIntVariable>(solidity::TypeProvider::uint256(), type, _uniqueName, _context);
		else
			var = make_shared<SymbolicIntVariable>(type, type, _uniqueName, _context);
	}
	else if (isMapping(_type.category()))
		var = make_shared<SymbolicMappingVariable>(type, _uniqueName, _context);
	else if (isArray(_type.category()))
		var = make_shared<SymbolicArrayVariable>(type, type, _uniqueName, _context);
	else if (isTuple(_type.category()))
		var = make_shared<SymbolicTupleVariable>(type, _uniqueName, _context);
	else if (isStringLiteral(_type.category()))
	{
		auto stringType = TypeProvider::stringMemory();
		var = make_shared<SymbolicArrayVariable>(stringType, type, _uniqueName, _context);
	}
	else
		solAssert(false, "");
	return make_pair(abstract, var);
}

bool isSupportedType(solidity::Type const& _type)
{
	return isSupportedType(_type.category());
}

bool isSupportedTypeDeclaration(solidity::Type const& _type)
{
	return isSupportedTypeDeclaration(_type.category());
}

bool isInteger(solidity::Type::Category _category)
{
	return _category == solidity::Type::Category::Integer;
}

bool isRational(solidity::Type::Category _category)
{
	return _category == solidity::Type::Category::RationalNumber;
}

bool isFixedBytes(solidity::Type::Category _category)
{
	return _category == solidity::Type::Category::FixedBytes;
}

bool isAddress(solidity::Type::Category _category)
{
	return _category == solidity::Type::Category::Address;
}

bool isContract(solidity::Type::Category _category)
{
	return _category == solidity::Type::Category::Contract;
}

bool isEnum(solidity::Type::Category _category)
{
	return _category == solidity::Type::Category::Enum;
}

bool isNumber(solidity::Type::Category _category)
{
	return isInteger(_category) ||
		isRational(_category) ||
		isFixedBytes(_category) ||
		isAddress(_category) ||
		isContract(_category) ||
		isEnum(_category);
}

bool isBool(solidity::Type::Category _category)
{
	return _category == solidity::Type::Category::Bool;
}

bool isFunction(solidity::Type::Category _category)
{
	return _category == solidity::Type::Category::Function;
}

bool isMapping(solidity::Type::Category _category)
{
	return _category == solidity::Type::Category::Mapping;
}

bool isArray(solidity::Type::Category _category)
{
	return _category == solidity::Type::Category::Array ||
		_category == solidity::Type::Category::StringLiteral;
}

bool isTuple(solidity::Type::Category _category)
{
	return _category == solidity::Type::Category::Tuple;
}

bool isStringLiteral(solidity::Type::Category _category)
{
	return _category == solidity::Type::Category::StringLiteral;
}

Expression minValue(solidity::IntegerType const& _type)
{
	return Expression(_type.minValue());
}

Expression maxValue(solidity::IntegerType const& _type)
{
	return Expression(_type.maxValue());
}

void setSymbolicZeroValue(SymbolicVariable const& _variable, EncodingContext& _context)
{
	setSymbolicZeroValue(_variable.currentValue(), _variable.type(), _context);
}

void setSymbolicZeroValue(Expression _expr, solidity::TypePointer const& _type, EncodingContext& _context)
{
	solAssert(_type, "");
	_context.addAssertion(_expr == zeroValue(_type));
}

Expression zeroValue(solidity::TypePointer const& _type)
{
	solAssert(_type, "");
	if (isSupportedType(_type->category()))
	{
		if (isNumber(_type->category()))
			return 0;
		if (isBool(_type->category()))
			return Expression(false);
		if (isArray(_type->category()) || isMapping(_type->category()))
		{
			if (auto arrayType = dynamic_cast<ArrayType const*>(_type))
				return Expression::const_array(Expression(arrayType), zeroValue(arrayType->baseType()));
			auto mappingType = dynamic_cast<MappingType const*>(_type);
			solAssert(mappingType, "");
			return Expression::const_array(Expression(mappingType), zeroValue(mappingType->valueType()));
		}
		solAssert(false, "");
	}
	// Unsupported types are abstracted as Int.
	return 0;
}

void setSymbolicUnknownValue(SymbolicVariable const& _variable, EncodingContext& _context)
{
	setSymbolicUnknownValue(_variable.currentValue(), _variable.type(), _context);
}

void setSymbolicUnknownValue(Expression _expr, solidity::TypePointer const& _type, EncodingContext& _context)
{
	solAssert(_type, "");
	if (isEnum(_type->category()))
	{
		auto enumType = dynamic_cast<solidity::EnumType const*>(_type);
		solAssert(enumType, "");
		_context.addAssertion(_expr >= 0);
		_context.addAssertion(_expr < enumType->numberOfMembers());
	}
	else if (isInteger(_type->category()))
	{
		auto intType = dynamic_cast<solidity::IntegerType const*>(_type);
		solAssert(intType, "");
		_context.addAssertion(_expr >= minValue(*intType));
		_context.addAssertion(_expr <= maxValue(*intType));
	}
}

}
}
}
