package gov.nist.csd.pm.policies.dac.consent;

import gov.nist.csd.pm.epp.FunctionEvaluator;
import gov.nist.csd.pm.epp.events.AssignToEvent;
import gov.nist.csd.pm.epp.events.EventContext;
import gov.nist.csd.pm.epp.functions.FunctionExecutor;
import gov.nist.csd.pm.exceptions.PMException;
import gov.nist.csd.pm.operations.OperationSet;
import gov.nist.csd.pm.pdp.PDP;
import gov.nist.csd.pm.pdp.services.UserContext;
import gov.nist.csd.pm.pip.graph.Graph;
import gov.nist.csd.pm.pip.graph.model.nodes.Node;
import gov.nist.csd.pm.pip.obligations.evr.EVRException;
import gov.nist.csd.pm.pip.obligations.model.functions.Function;

import static gov.nist.csd.pm.operations.Operations.ALL_OPS;
import static gov.nist.csd.pm.pip.graph.model.nodes.NodeType.OA;
import static gov.nist.csd.pm.pip.graph.model.nodes.NodeType.UA;
import static gov.nist.csd.pm.policies.dac.consent.ConsentPolicy.GUARDIAN_PROPERTY;

public class ConsentEVRFunction implements FunctionExecutor {
    @Override
    public String getFunctionName() {
        return "config_consent";
    }

    @Override
    public int numParams() {
        return 0;
    }

    @Override
    public Object exec(UserContext userContext, EventContext eventCtx, PDP pdp, Function function, FunctionEvaluator functionEvaluator) throws PMException {
        if (!(eventCtx instanceof AssignToEvent)) {
            throw new EVRException("config_consent expected an AssignToEvent but got " + eventCtx.getClass());
        }
        AssignToEvent assignToEvent = (AssignToEvent)eventCtx;

        Node userNode = assignToEvent.getChildNode();

        // create the consent configuration for this user -- ths user has already been assigned to dac_users and dac_users2
        // create a dac UA for this user
        Graph graph = pdp.getGraphService(userContext);
        Node uaNode = graph.createNode(userNode.getName() + "_UA", UA, Node.toProperties("user", userNode.getName()), "DAC_default_UA");

        // assign user to UA
        graph.assign(userNode.getName(), uaNode.getName());

        Node cont = graph.createNode(userNode.getName() + "_consent_container", OA, Node.toProperties("consent", userNode.getName()), "DAC_default_OA");
        Node group = graph.createNode(userNode.getName() + "_consent_group", UA, Node.toProperties("consent", userNode.getName()), "DAC_default_UA");

        Node accessRequests = graph.createNode(userNode.getName() + "_access_requests", OA,
                Node.toProperties("access_requests", userNode.getName(), "type", "requests"), cont.getName());
        Node approved = graph.createNode(userNode.getName() + "_approved_requests", OA,
                Node.toProperties("access_requests", userNode.getName(), "type", "approved_requests"), cont.getName());
        Node declined = graph.createNode(userNode.getName() + "_declined_requests", OA,
                Node.toProperties("access_requests", userNode.getName(), "type", "declined_requests"), cont.getName());

        // assign the approved container to dac_users_request_containers
        graph.assign(accessRequests.getName(), "dac_users_request_containers");

        // create group admin ua
        // assign the admin to the daf default ua to avoid a multiple edge situation with the group UA
        Node adminNode = graph.createNode(group.getName() + "_admin", UA, null, "DAC_default_UA");
        // assign the user to the admin
        graph.assign(userNode.getName(), adminNode.getName());

        // if the user has a guardian, assign them as well
        if (userNode.getProperties().containsKey(GUARDIAN_PROPERTY)) {
            graph.assign(userNode.getProperties().get(GUARDIAN_PROPERTY), adminNode.getName());
        }

        // associate the admin and the container
        graph.associate(adminNode.getName(), cont.getName(), new OperationSet(ALL_OPS));
        // associate the admin and the group
        graph.associate(adminNode.getName(), group.getName(), new OperationSet(ALL_OPS));

        return null;
    }
}
