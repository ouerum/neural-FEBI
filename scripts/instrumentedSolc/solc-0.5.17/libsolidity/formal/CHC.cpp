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

#include <libsolidity/formal/CHC.h>

#include <libsolidity/formal/CHCSmtLib2Interface.h>

#ifdef HAVE_Z3
#include <libsolidity/formal/Z3CHCInterface.h>
#endif

#include <libsolidity/formal/SymbolicTypes.h>

#include <libsolidity/ast/TypeProvider.h>

using namespace std;
using namespace dev;
using namespace langutil;
using namespace dev::solidity;

CHC::CHC(
	smt::EncodingContext& _context,
	ErrorReporter& _errorReporter,
	map<h256, string> const& _smtlib2Responses,
	smt::SMTSolverChoice _enabledSolvers
):
	SMTEncoder(_context),
#ifdef HAVE_Z3
	m_interface(
		_enabledSolvers.z3 ?
		dynamic_pointer_cast<smt::CHCSolverInterface>(make_shared<smt::Z3CHCInterface>()) :
		dynamic_pointer_cast<smt::CHCSolverInterface>(make_shared<smt::CHCSmtLib2Interface>(_smtlib2Responses))
	),
#else
	m_interface(make_shared<smt::CHCSmtLib2Interface>(_smtlib2Responses)),
#endif
	m_outerErrorReporter(_errorReporter)
{
	(void)_smtlib2Responses;
	(void)_enabledSolvers;
}

void CHC::analyze(SourceUnit const& _source)
{
	solAssert(_source.annotation().experimentalFeatures.count(ExperimentalFeature::SMTChecker), "");

#ifdef HAVE_Z3
	auto z3Interface = dynamic_pointer_cast<smt::Z3CHCInterface>(m_interface);
	solAssert(z3Interface, "");
	m_context.setSolver(z3Interface->z3Interface());
#else
	auto smtlib2Interface = dynamic_pointer_cast<smt::CHCSmtLib2Interface>(m_interface);
	solAssert(smtlib2Interface, "");
	m_context.setSolver(smtlib2Interface->smtlib2Interface());
#endif
	m_context.clear();
	m_context.setAssertionAccumulation(false);
	m_variableUsage.setFunctionInlining(false);

	auto boolSort = make_shared<smt::Sort>(smt::Kind::Bool);
	auto genesisSort = make_shared<smt::FunctionSort>(
		vector<smt::SortPointer>(),
		boolSort
	);
	m_genesisPredicate = createSymbolicBlock(genesisSort, "genesis");
	auto genesis = (*m_genesisPredicate)({});
	addRule(genesis, genesis.name);

	_source.accept(*this);
}

vector<string> CHC::unhandledQueries() const
{
	if (auto smtlib2 = dynamic_pointer_cast<smt::CHCSmtLib2Interface>(m_interface))
		return smtlib2->unhandledQueries();

	return {};
}

bool CHC::visit(ContractDefinition const& _contract)
{
	if (!shouldVisit(_contract))
		return false;

	reset();

	initContract(_contract);

	m_stateVariables = _contract.stateVariablesIncludingInherited();

	for (auto const& var: m_stateVariables)
		// SMT solvers do not support function types as arguments.
		if (var->type()->category() == Type::Category::Function)
			m_stateSorts.push_back(make_shared<smt::Sort>(smt::Kind::Int));
		else
			m_stateSorts.push_back(smt::smtSort(*var->type()));

	clearIndices(&_contract);

	string suffix = _contract.name() + "_" + to_string(_contract.id());
	m_interfacePredicate = createSymbolicBlock(interfaceSort(), "interface_" + suffix);

	// TODO create static instances for Bool/Int sorts in SolverInterface.
	auto boolSort = make_shared<smt::Sort>(smt::Kind::Bool);
	auto errorFunctionSort = make_shared<smt::FunctionSort>(
		vector<smt::SortPointer>(),
		boolSort
	);

	m_errorPredicate = createSymbolicBlock(errorFunctionSort, "error_" + suffix);
	m_constructorPredicate = createSymbolicBlock(constructorSort(), "implicit_constructor_" + to_string(_contract.id()));
	auto stateExprs = currentStateVariables();
	setCurrentBlock(*m_interfacePredicate, &stateExprs);

	SMTEncoder::visit(_contract);
	return false;
}

void CHC::endVisit(ContractDefinition const& _contract)
{
	if (!shouldVisit(_contract))
		return;

	for (auto const& var: m_stateVariables)
	{
		solAssert(m_context.knownVariable(*var), "");
		m_context.setZeroValue(*var);
	}
	auto genesisPred = (*m_genesisPredicate)({});
	auto implicitConstructor = (*m_constructorPredicate)(currentStateVariables());
	connectBlocks(genesisPred, implicitConstructor);
	m_currentBlock = implicitConstructor;

	if (auto constructor = _contract.constructor())
		constructor->accept(*this);
	else
		inlineConstructorHierarchy(_contract);

	connectBlocks(m_currentBlock, interface());

	for (unsigned i = 0; i < m_verificationTargets.size(); ++i)
	{
		auto const& target = m_verificationTargets.at(i);
		auto errorAppl = error(i + 1);
		if (query(errorAppl, target->location()))
			m_safeAssertions.insert(target);
	}

	SMTEncoder::endVisit(_contract);
}

bool CHC::visit(FunctionDefinition const& _function)
{
	if (!shouldVisit(_function))
		return false;

	// This is the case for base constructor inlining.
	if (m_currentFunction)
	{
		solAssert(m_currentFunction->isConstructor(), "");
		solAssert(_function.isConstructor(), "");
		solAssert(_function.scope() != m_currentContract, "");
		SMTEncoder::visit(_function);
		return false;
	}

	solAssert(!m_currentFunction, "Inlining internal function calls not yet implemented");
	m_currentFunction = &_function;

	initFunction(_function);

	auto functionEntryBlock = createBlock(m_currentFunction);
	auto bodyBlock = createBlock(&m_currentFunction->body());

	auto functionPred = predicate(*functionEntryBlock, currentFunctionVariables());
	auto bodyPred = predicate(*bodyBlock);

	connectBlocks(m_currentBlock, functionPred);
	connectBlocks(functionPred, bodyPred);

	setCurrentBlock(*bodyBlock);

	SMTEncoder::visit(*m_currentFunction);

	return false;
}

void CHC::endVisit(FunctionDefinition const& _function)
{
	if (!shouldVisit(_function))
		return;

	// This is the case for base constructor inlining.
	if (m_currentFunction != &_function)
	{
		solAssert(m_currentFunction && m_currentFunction->isConstructor(), "");
		solAssert(_function.isConstructor(), "");
		solAssert(_function.scope() != m_currentContract, "");
	}
	else
	{
		// We create an extra exit block for constructors that simply
		// connects to the interface in case an explicit constructor
		// exists in the hierarchy.
		// It is not connected directly here, as normal functions are,
		// because of the case where there are only implicit constructors.
		// This is done in endVisit(ContractDefinition).
		if (_function.isConstructor())
		{
			auto constructorExit = createSymbolicBlock(interfaceSort(), "constructor_exit_" + to_string(_function.id()));
			connectBlocks(m_currentBlock, predicate(*constructorExit, currentStateVariables()));
			clearIndices(m_currentContract, m_currentFunction);
			auto stateExprs = currentStateVariables();
			setCurrentBlock(*constructorExit, &stateExprs);
		}
		else
		{
			connectBlocks(m_currentBlock, interface());
			clearIndices(m_currentContract, m_currentFunction);
			auto stateExprs = currentStateVariables();
			setCurrentBlock(*m_interfacePredicate, &stateExprs);
		}
		m_currentFunction = nullptr;
	}

	SMTEncoder::endVisit(_function);
}

bool CHC::visit(IfStatement const& _if)
{
	solAssert(m_currentFunction, "");

	bool unknownFunctionCallWasSeen = m_unknownFunctionCallSeen;
	m_unknownFunctionCallSeen = false;

	solAssert(m_currentFunction, "");
	auto const& functionBody = m_currentFunction->body();

	auto ifHeaderBlock = createBlock(&_if, "if_header_");
	auto trueBlock = createBlock(&_if.trueStatement(), "if_true_");
	auto falseBlock = _if.falseStatement() ? createBlock(_if.falseStatement(), "if_false_") : nullptr;
	auto afterIfBlock = createBlock(&functionBody);

	connectBlocks(m_currentBlock, predicate(*ifHeaderBlock));

	setCurrentBlock(*ifHeaderBlock);
	_if.condition().accept(*this);
	auto condition = expr(_if.condition());

	connectBlocks(m_currentBlock, predicate(*trueBlock), condition);
	if (_if.falseStatement())
		connectBlocks(m_currentBlock, predicate(*falseBlock), !condition);
	else
		connectBlocks(m_currentBlock, predicate(*afterIfBlock), !condition);

	setCurrentBlock(*trueBlock);
	_if.trueStatement().accept(*this);
	connectBlocks(m_currentBlock, predicate(*afterIfBlock));

	if (_if.falseStatement())
	{
		setCurrentBlock(*falseBlock);
		_if.falseStatement()->accept(*this);
		connectBlocks(m_currentBlock, predicate(*afterIfBlock));
	}

	setCurrentBlock(*afterIfBlock);

	if (m_unknownFunctionCallSeen)
		eraseKnowledge();

	m_unknownFunctionCallSeen = unknownFunctionCallWasSeen;

	return false;
}

bool CHC::visit(WhileStatement const& _while)
{
	bool unknownFunctionCallWasSeen = m_unknownFunctionCallSeen;
	m_unknownFunctionCallSeen = false;

	solAssert(m_currentFunction, "");
	auto const& functionBody = m_currentFunction->body();

	auto namePrefix = string(_while.isDoWhile() ? "do_" : "") + "while";
	auto loopHeaderBlock = createBlock(&_while, namePrefix + "_header_");
	auto loopBodyBlock = createBlock(&_while.body(), namePrefix + "_body_");
	auto afterLoopBlock = createBlock(&functionBody);

	auto outerBreakDest = m_breakDest;
	auto outerContinueDest = m_continueDest;
	m_breakDest = afterLoopBlock.get();
	m_continueDest = loopHeaderBlock.get();

	if (_while.isDoWhile())
		_while.body().accept(*this);

	connectBlocks(m_currentBlock, predicate(*loopHeaderBlock));

	setCurrentBlock(*loopHeaderBlock);

	_while.condition().accept(*this);
	auto condition = expr(_while.condition());

	connectBlocks(m_currentBlock, predicate(*loopBodyBlock), condition);
	connectBlocks(m_currentBlock, predicate(*afterLoopBlock), !condition);

	// Loop body visit.
	setCurrentBlock(*loopBodyBlock);
	_while.body().accept(*this);

	m_breakDest = outerBreakDest;
	m_continueDest = outerContinueDest;

	// Back edge.
	connectBlocks(m_currentBlock, predicate(*loopHeaderBlock));
	setCurrentBlock(*afterLoopBlock);

	if (m_unknownFunctionCallSeen)
		eraseKnowledge();

	m_unknownFunctionCallSeen = unknownFunctionCallWasSeen;

	return false;
}

bool CHC::visit(ForStatement const& _for)
{
	bool unknownFunctionCallWasSeen = m_unknownFunctionCallSeen;
	m_unknownFunctionCallSeen = false;

	solAssert(m_currentFunction, "");
	auto const& functionBody = m_currentFunction->body();

	auto loopHeaderBlock = createBlock(&_for, "for_header_");
	auto loopBodyBlock = createBlock(&_for.body(), "for_body_");
	auto afterLoopBlock = createBlock(&functionBody);
	auto postLoop = _for.loopExpression();
	auto postLoopBlock = postLoop ? createBlock(postLoop, "for_post_") : nullptr;

	auto outerBreakDest = m_breakDest;
	auto outerContinueDest = m_continueDest;
	m_breakDest = afterLoopBlock.get();
	m_continueDest = postLoop ? postLoopBlock.get() : loopHeaderBlock.get();

	if (auto init = _for.initializationExpression())
		init->accept(*this);

	connectBlocks(m_currentBlock, predicate(*loopHeaderBlock));
	setCurrentBlock(*loopHeaderBlock);

	auto condition = smt::Expression(true);
	if (auto forCondition = _for.condition())
	{
		forCondition->accept(*this);
		condition = expr(*forCondition);
	}

	connectBlocks(m_currentBlock, predicate(*loopBodyBlock), condition);
	connectBlocks(m_currentBlock, predicate(*afterLoopBlock), !condition);

	// Loop body visit.
	setCurrentBlock(*loopBodyBlock);
	_for.body().accept(*this);

	if (postLoop)
	{
		connectBlocks(m_currentBlock, predicate(*postLoopBlock));
		setCurrentBlock(*postLoopBlock);
		postLoop->accept(*this);
	}

	m_breakDest = outerBreakDest;
	m_continueDest = outerContinueDest;

	// Back edge.
	connectBlocks(m_currentBlock, predicate(*loopHeaderBlock));
	setCurrentBlock(*afterLoopBlock);

	if (m_unknownFunctionCallSeen)
		eraseKnowledge();

	m_unknownFunctionCallSeen = unknownFunctionCallWasSeen;

	return false;
}

void CHC::endVisit(FunctionCall const& _funCall)
{
	solAssert(_funCall.annotation().kind != FunctionCallKind::Unset, "");

	if (_funCall.annotation().kind != FunctionCallKind::FunctionCall)
	{
		SMTEncoder::endVisit(_funCall);
		return;
	}

	FunctionType const& funType = dynamic_cast<FunctionType const&>(*_funCall.expression().annotation().type);
	switch (funType.kind())
	{
	case FunctionType::Kind::Assert:
		visitAssert(_funCall);
		SMTEncoder::endVisit(_funCall);
		break;
	case FunctionType::Kind::Internal:
	case FunctionType::Kind::External:
	case FunctionType::Kind::DelegateCall:
	case FunctionType::Kind::BareCall:
	case FunctionType::Kind::BareCallCode:
	case FunctionType::Kind::BareDelegateCall:
	case FunctionType::Kind::BareStaticCall:
	case FunctionType::Kind::Creation:
	case FunctionType::Kind::KECCAK256:
	case FunctionType::Kind::ECRecover:
	case FunctionType::Kind::SHA256:
	case FunctionType::Kind::RIPEMD160:
	case FunctionType::Kind::BlockHash:
	case FunctionType::Kind::AddMod:
	case FunctionType::Kind::MulMod:
		SMTEncoder::endVisit(_funCall);
		unknownFunctionCall(_funCall);
		break;
	default:
		SMTEncoder::endVisit(_funCall);
		break;
	}

	createReturnedExpressions(_funCall);
}

void CHC::endVisit(Break const& _break)
{
	solAssert(m_breakDest, "");
	connectBlocks(m_currentBlock, predicate(*m_breakDest));
	auto breakGhost = createBlock(&_break, "break_ghost_");
	m_currentBlock = predicate(*breakGhost);
}

void CHC::endVisit(Continue const& _continue)
{
	solAssert(m_continueDest, "");
	connectBlocks(m_currentBlock, predicate(*m_continueDest));
	auto continueGhost = createBlock(&_continue, "continue_ghost_");
	m_currentBlock = predicate(*continueGhost);
}

void CHC::visitAssert(FunctionCall const& _funCall)
{
	auto const& args = _funCall.arguments();
	solAssert(args.size() == 1, "");
	solAssert(args.front()->annotation().type->category() == Type::Category::Bool, "");

	createErrorBlock();

	smt::Expression assertNeg = !(m_context.expression(*args.front())->currentValue());
	connectBlocks(m_currentBlock, error(), currentPathConditions() && assertNeg);

	m_verificationTargets.push_back(&_funCall);
}

void CHC::unknownFunctionCall(FunctionCall const&)
{
	/// Function calls are not handled at the moment,
	/// so always erase knowledge.
	/// TODO remove when function calls get predicates/blocks.
	eraseKnowledge();

	/// Used to erase outer scope knowledge in loops and ifs.
	/// TODO remove when function calls get predicates/blocks.
	m_unknownFunctionCallSeen = true;
}

void CHC::reset()
{
	m_stateSorts.clear();
	m_stateVariables.clear();
	m_verificationTargets.clear();
	m_safeAssertions.clear();
	m_unknownFunctionCallSeen = false;
	m_breakDest = nullptr;
	m_continueDest = nullptr;
}

void CHC::eraseKnowledge()
{
	resetStateVariables();
	m_context.resetVariables([&](VariableDeclaration const& _variable) { return _variable.hasReferenceOrMappingType(); });
}

bool CHC::shouldVisit(ContractDefinition const& _contract) const
{
	if (
		_contract.isLibrary() ||
		_contract.isInterface()
	)
		return false;
	return true;
}

bool CHC::shouldVisit(FunctionDefinition const& _function) const
{
	if (
		_function.isPublic() &&
		_function.isImplemented()
	)
		return true;
	return false;
}

void CHC::setCurrentBlock(
	smt::SymbolicFunctionVariable const& _block,
	vector<smt::Expression> const* _arguments
)
{
	m_context.popSolver();
	solAssert(m_currentContract, "");
	clearIndices(m_currentContract, m_currentFunction);
	m_context.pushSolver();
	if (_arguments)
		m_currentBlock = predicate(_block, *_arguments);
	else
		m_currentBlock = predicate(_block);
}

smt::SortPointer CHC::constructorSort()
{
	// TODO this will change once we support function calls.
	return interfaceSort();
}

smt::SortPointer CHC::interfaceSort()
{
	auto boolSort = make_shared<smt::Sort>(smt::Kind::Bool);
	return make_shared<smt::FunctionSort>(
		m_stateSorts,
		boolSort
	);
}

smt::SortPointer CHC::sort(FunctionDefinition const& _function)
{
	auto boolSort = make_shared<smt::Sort>(smt::Kind::Bool);
	vector<smt::SortPointer> varSorts;
	for (auto const& var: _function.parameters() + _function.returnParameters())
	{
		// SMT solvers do not support function types as arguments.
		if (var->type()->category() == Type::Category::Function)
			varSorts.push_back(make_shared<smt::Sort>(smt::Kind::Int));
		else
			varSorts.push_back(smt::smtSort(*var->type()));
	}
	return make_shared<smt::FunctionSort>(
		m_stateSorts + varSorts,
		boolSort
	);
}

smt::SortPointer CHC::sort(ASTNode const* _node)
{
	if (auto funDef = dynamic_cast<FunctionDefinition const*>(_node))
		return sort(*funDef);

	auto fSort = dynamic_pointer_cast<smt::FunctionSort>(sort(*m_currentFunction));
	solAssert(fSort, "");

	auto boolSort = make_shared<smt::Sort>(smt::Kind::Bool);
	vector<smt::SortPointer> varSorts;
	for (auto const& var: m_currentFunction->localVariables())
	{
		// SMT solvers do not support function types as arguments.
		if (var->type()->category() == Type::Category::Function)
			varSorts.push_back(make_shared<smt::Sort>(smt::Kind::Int));
		else
			varSorts.push_back(smt::smtSort(*var->type()));
	}
	return make_shared<smt::FunctionSort>(
		fSort->domain + varSorts,
		boolSort
	);
}

unique_ptr<smt::SymbolicFunctionVariable> CHC::createSymbolicBlock(smt::SortPointer _sort, string const& _name)
{
	auto block = make_unique<smt::SymbolicFunctionVariable>(
		_sort,
		_name,
		m_context
	);
	m_interface->registerRelation(block->currentFunctionValue());
	return block;
}

smt::Expression CHC::interface()
{
	vector<smt::Expression> paramExprs;
	for (auto const& var: m_stateVariables)
		paramExprs.push_back(m_context.variable(*var)->currentValue());
	return (*m_interfacePredicate)(paramExprs);
}

smt::Expression CHC::error()
{
	return (*m_errorPredicate)({});
}

smt::Expression CHC::error(unsigned _idx)
{
	return m_errorPredicate->functionValueAtIndex(_idx)({});
}

unique_ptr<smt::SymbolicFunctionVariable> CHC::createBlock(ASTNode const* _node, string const& _prefix)
{
	return createSymbolicBlock(sort(_node),
		"block_" +
		uniquePrefix() +
		"_" +
		_prefix +
		predicateName(_node));
}

void CHC::createErrorBlock()
{
	solAssert(m_errorPredicate, "");
	m_errorPredicate->increaseIndex();
	m_interface->registerRelation(m_errorPredicate->currentFunctionValue());
}

void CHC::connectBlocks(smt::Expression const& _from, smt::Expression const& _to, smt::Expression const& _constraints)
{
	smt::Expression edge = smt::Expression::implies(
		_from && m_context.assertions() && _constraints,
		_to
	);
	addRule(edge, _from.name + "_to_" + _to.name);
}

vector<smt::Expression> CHC::currentStateVariables()
{
	solAssert(m_currentContract, "");
	vector<smt::Expression> exprs;
	for (auto const& var: m_stateVariables)
		exprs.push_back(m_context.variable(*var)->currentValue());
	return exprs;
}

vector<smt::Expression> CHC::currentFunctionVariables()
{
	vector<smt::Expression> paramExprs;
	if (m_currentFunction)
		for (auto const& var: m_currentFunction->parameters() + m_currentFunction->returnParameters())
			paramExprs.push_back(m_context.variable(*var)->currentValue());
	return currentStateVariables() + paramExprs;
}

vector<smt::Expression> CHC::currentBlockVariables()
{
	vector<smt::Expression> paramExprs;
	if (m_currentFunction)
		for (auto const& var: m_currentFunction->localVariables())
			paramExprs.push_back(m_context.variable(*var)->currentValue());
	return currentFunctionVariables() + paramExprs;
}

string CHC::predicateName(ASTNode const* _node)
{
	string prefix;
	if (auto funDef = dynamic_cast<FunctionDefinition const*>(_node))
	{
		prefix = funDef->isConstructor() ?
			"constructor" :
			funDef->isFallback() ?
				"fallback" :
				"function_" + funDef->name();
		prefix += "_";
	}
	return prefix + to_string(_node->id());
}

smt::Expression CHC::predicate(smt::SymbolicFunctionVariable const& _block)
{
	return _block(currentBlockVariables());
}

smt::Expression CHC::predicate(
	smt::SymbolicFunctionVariable const& _block,
	vector<smt::Expression> const& _arguments
)
{
	return _block(_arguments);
}

void CHC::addRule(smt::Expression const& _rule, string const& _ruleName)
{
	m_interface->addRule(_rule, _ruleName);
}

bool CHC::query(smt::Expression const& _query, langutil::SourceLocation const& _location)
{
	smt::CheckResult result;
	vector<string> values;
	tie(result, values) = m_interface->query(_query);
	switch (result)
	{
	case smt::CheckResult::SATISFIABLE:
		break;
	case smt::CheckResult::UNSATISFIABLE:
		return true;
	case smt::CheckResult::UNKNOWN:
		break;
	case smt::CheckResult::CONFLICTING:
		m_outerErrorReporter.warning(_location, "At least two SMT solvers provided conflicting answers. Results might not be sound.");
		break;
	case smt::CheckResult::ERROR:
		m_outerErrorReporter.warning(_location, "Error trying to invoke SMT solver.");
		break;
	}
	return false;
}

string CHC::uniquePrefix()
{
	return to_string(m_blockCounter++);
}
