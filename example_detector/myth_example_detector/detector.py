from mythril.analysis import solver
from mythril.plugin.interface import MythrilPlugin
from mythril.analysis.report import Issue
from mythril.analysis.swc_data import UNPROTECTED_SELFDESTRUCT
from mythril.exceptions import UnsatError
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.ethereum.transaction.symbolic import ACTORS
from mythril.laser.smt.bool import And
from mythril.laser.smt import Extract, symbol_factory
from mythril.laser.ethereum.transaction.transaction_models import (
    ContractCreationTransaction,
)
from mythril.laser.ethereum.transaction.symbolic import ACTORS

import logging
from copy import copy
from typing import List
log = logging.getLogger(__name__)


class OwnershipDetector(DetectionModule, MythrilPlugin):
    """This module checks for ownership vulnerabilities"""

    # Plugin Meta info
    author = "Joran Honig"
    plugin_license = "MIT"
    plugin_type = "Detection Module"
    plugin_version = "0.0.1 "
    plugin_description = \
        "This is an example detection module plugin which finds ownership takeover vulnerabilities.\n" \
        "This is largely copy of the reachable exceptions module already present in Mythril."
    plugin_default_enabled = True

    # Detection Module Meta
    name = "Detects ownership takeover vulnerabilities"
    swc_id = None
    description = "This detection module automatically finds vulnerabilities" \
                  "which allow an attacker to take over ownership.\n" \
                  "This detection module assumes that the ownership variable" \
                  "is located at address 0, offset 0, and will detect any possible method" \
                  "to make owner = attacker."
    entry_point = EntryPoint.CALLBACK
    pre_hooks = ["SSTORE"]

    def _execute(self, state: GlobalState) -> None:
        """Minimal wrapper around _analyze_state()
        For more complex detectors with multiple hooks, having a wrapper to orchestrate the detection
        comes in really handy.
        Check out mythril.analysis.module.modules.* for the detection modules shipped with Mythril!
        """
        issues = self._analyze_state(state)
        self.issues.extend(issues)

    @staticmethod
    def _analyze_state(state) -> List[Issue]:
        instruction = state.get_current_instruction()
        address, value = state.mstate.stack[-1], state.mstate.stack[-2]

        target_slot = 0
        target_offset = 0

        # In the following array we'll describe all the conditions that need to hold for a take over of ownership
        vulnerable_conditions = [
            # Lets check that we're writing to address 0 (where the owner variable is located
            address == target_slot,
            # There is only a vulnerability if before the writing to the owner variable: owner != attacker
            Extract(
                20*8 + target_offset,
                0 + target_offset,
                state.environment.active_account.storage[symbol_factory.BitVecVal(0, 256)]
            ) != ACTORS.attacker,
            # There IS a vulnerability if the value being written to owner is the attacker address
            Extract(
                20*8 + target_offset,
                0 + target_offset,
            ) == ACTORS.attacker,
            # Lets only look for cases where the attacker makes themselves the owner by saying that the attacker
            # is the sender of this transaction
            state.environment.sender == ACTORS.attacker,
        ]

        try:
            # vulnerable_conditions describes when there is a vulnerability
            # lets check if the conditions are actually satisfiable by running the following command:
            # This will raise an UnsatError if the vulnerable_conditions are not satisfiable (i.e. not possible)
            transaction_sequence = solver.get_transaction_sequence(
                state,
                state.world_state.constraints
                + vulnerable_conditions,
            )
            # Note that get_transaction_sequence also gives us `transaction_sequence` which gives us a concrete
            # transaction trace that can be used to exploit/demonstrate the vulnerability.

            # Lets register an issue with Mythril so that the vulnerability is reported to the user!
            return [Issue(
                contract=state.environment.active_account.contract_name,
                function_name=state.environment.active_function_name,
                address=instruction["address"],
                swc_id='000',
                bytecode=state.environment.code.bytecode,
                title="Ownership Takeover",
                severity="High",
                description_head="An attacker can take over ownership of this contract.",
                description_tail="",
                transaction_sequence=transaction_sequence,
                gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
            )]
        except UnsatError:
            # Sadly (or happily), no vulnerabilities were found here.
            log.debug("Vulnerable conditions were not satisfiable")
            return list()
