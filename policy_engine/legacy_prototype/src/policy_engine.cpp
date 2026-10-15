#include "policy_engine.h"

using namespace std;

PolicyDecision PolicyEngine::selectPolicy(
    const IPCMessage& message,
    const RiskResult& risk
) {

    bool resourceConstrained =
        message.cpuUsage >= 80 ||
        message.memoryUsage >= 80;

    bool criticalThreat =
        message.threat == ThreatLevel::CRITICAL;

    bool criticalCommunication =
        message.criticality == Criticality::CRITICAL;

    SecurityPolicy basePolicy;

    if (risk.score <= 6) {

        basePolicy = SecurityPolicy::BASIC;

    }
    else if (risk.score <= 9) {

        basePolicy = SecurityPolicy::CLASSICAL;

    }
    else if (risk.score <= 12) {

        basePolicy = SecurityPolicy::HYBRID;

    }
    else {

        basePolicy = SecurityPolicy::POST_QUANTUM;
    }

    SecurityPolicy finalPolicy = basePolicy;

    bool securityEscalated = false;
    bool resourceAdapted = false;

    string reason;

    /*
        Security escalation has highest priority.

        Critical threats or critical communication
        should receive POST-QUANTUM protection.
    */

    if (criticalThreat || criticalCommunication) {

        if (finalPolicy != SecurityPolicy::POST_QUANTUM) {

            finalPolicy = SecurityPolicy::POST_QUANTUM;
            securityEscalated = true;
            reason = "Critical security condition detected";
        }
        else {

            reason = "Critical risk level";
        }
    }

    /*
        Resource-aware adaptation.

        Resource constraints can downgrade HYBRID
        protection, but never POST-QUANTUM protection
        required for critical communication.
    */

    else if (resourceConstrained &&
             finalPolicy == SecurityPolicy::HYBRID) {

        finalPolicy = SecurityPolicy::CLASSICAL;

        resourceAdapted = true;

        reason = "Resource-constrained system";
    }

    /*
        No adaptation.
    */

    else {

        if (finalPolicy == SecurityPolicy::BASIC) {

            reason = "Low risk communication";
        }

        else if (finalPolicy == SecurityPolicy::CLASSICAL) {

            reason = "Moderate risk communication";
        }

        else if (finalPolicy == SecurityPolicy::HYBRID) {

            reason = "High risk with sufficient resources";
        }

        else {

            reason = "Critical risk level";
        }
    }

    bool adapted =
        (basePolicy != finalPolicy);

    return {
        basePolicy,
        finalPolicy,
        adapted,
        securityEscalated,
        resourceAdapted,
        reason
    };
}