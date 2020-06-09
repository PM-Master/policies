package gov.nist.csd.pm.policies.dac.consent;

import gov.nist.csd.pm.epp.functions.FunctionExecutor;
import gov.nist.csd.pm.exceptions.PMException;
import gov.nist.csd.pm.operations.OperationSet;
import gov.nist.csd.pm.pdp.PDP;
import gov.nist.csd.pm.pdp.services.UserContext;
import gov.nist.csd.pm.pip.graph.Graph;
import gov.nist.csd.pm.pip.graph.model.nodes.Node;
import gov.nist.csd.pm.pip.obligations.evr.EVRException;
import gov.nist.csd.pm.pip.obligations.evr.EVRParser;
import gov.nist.csd.pm.pip.obligations.model.Obligation;
import gov.nist.csd.pm.pip.prohibitions.Prohibitions;
import gov.nist.csd.pm.pip.prohibitions.model.Prohibition;
import gov.nist.csd.pm.policies.dac.consent.model.Consent;
import gov.nist.csd.pm.policies.dac.consent.model.ConsentRequest;

import java.util.*;

import static gov.nist.csd.pm.pip.graph.model.nodes.NodeType.OA;
import static gov.nist.csd.pm.pip.graph.model.nodes.NodeType.UA;

public class ConsentPolicy {

    private static final String CONSENT_PROPERTY = "consent";
    private static final String CONSENTER_PROPERTY = "consenter";
    private static final String CONSENTEE_PROPERTY = "consentee";
    public static final String PERMISSIONS_PROPERTY = "permissions";
    private static final String NODES_PROPERTY = "nodes";
    private static final String PROHIBITIONS_PROPERTY = "prohibitions";
    public static final String REQUESTER_PROPERTY = "requester";
    public static final String USER_PROPERTY = "user";

    private Graph graph;
    private Prohibitions prohibitions;

    public ConsentPolicy(PDP pdp, UserContext userContext) {
        this.graph = pdp.getGraphService(userContext);
        this.prohibitions = pdp.getProhibitionsService(new UserContext("super", ""));
    }

    private String getDenyName(String consenter, String consentee, List<String> permissions, List<String> conts) {
        return "for-" + consenter + "-deny-" + consentee + "-" + permissions + "-on-" + conts;
    }

    public void createConsentRequest(String requester, String user, List<String> permissions) throws PMException {
        // get the access request container for the user
        Node accessRequests = graph.getNode(OA, Node.toProperties("access_requests", user, "type", "requests"));

        graph.createNode("request_" + requester + "_" + permissions + "_" + user,
                OA,
                Node.toProperties(
                        "type", "access_request",
                        "requester", requester,
                        "user", user,
                        "permissions", String.join(",", permissions)
                ),
                accessRequests.getName());
    }

    public List<ConsentRequest> getRequesterRequests(String requester) throws PMException {
        return getRequests(Node.toProperties(
                REQUESTER_PROPERTY, requester,
                "type", "access_request")
        );
    }

    public List<ConsentRequest> getUserRequests(String user) throws PMException {
        return getRequests(Node.toProperties(
                USER_PROPERTY, user,
                "type", "access_request")
        );
    }

    private List<ConsentRequest> getRequests(Map<String, String> properties) throws PMException {
        Set<Node> search = graph.search(OA, properties);

        List<ConsentRequest> requests = new ArrayList<>();
        for (Node node : search) {
            Map<String, String> props = node.getProperties();
            String permStr = props.get(PERMISSIONS_PROPERTY);
            String user = props.get(USER_PROPERTY);
            String requester = props.get(REQUESTER_PROPERTY);

            List<String> perms = Arrays.asList(permStr.split(","));

            ConsentRequest request = new ConsentRequest();
            request.setRequester(requester);
            request.setUser(user);
            request.setPermissions(perms);

            requests.add(request);
        }

        return requests;
    }

    /**
     * get the consents that the given target is the target of.
     * @param consenter the target of the consents to return
     * @return
     */
    public List<Consent> getConsenterPolicies(String consenter) throws PMException {
        List<Consent> consents = new ArrayList<>();
        // search for OA nodes with property consent=target
        Set<Node> search = graph.search(OA, Node.toProperties(CONSENTER_PROPERTY, consenter));
        for (Node node : search) {
            Consent consent = new Consent();
            consent.setConsenter(consenter);

            // all consent info is stored in the properties of the consent node
            Map<String, String> properties = node.getProperties();

            String consentee = properties.get(CONSENTEE_PROPERTY);
            consent.setConsentee(consentee);

            String permsStr = properties.get(PERMISSIONS_PROPERTY);
            String nodesStr = properties.get(NODES_PROPERTY);
            String prosStr = properties.get(PROHIBITIONS_PROPERTY);

            if (permsStr == null) {
                continue;
            }

            OperationSet ops = new OperationSet(permsStr.split(","));
            consent.setPermissions(ops);

            if (!nodesStr.isEmpty()) {
                String[] pieces = nodesStr.split(",");
                for (String name : pieces) {
                    consent.addNode(graph.getNode(name));
                }
            }

            consent.setProhibitions(getProhibitions(consenter, consentee));

            consents.add(consent);
        }

        return consents;
    }

    /**
     * get the consents that the given user is the consentee of (receiving the consent).
     * @param consentee the target of the consents to return
     * @return the set of consents the user has been given
     */
    public List<Consent> getConsenteePolicies(String consentee) throws PMException {
        List<Consent> consents = new ArrayList<>();
        Set<Node> search = graph.search(OA, Node.toProperties(CONSENTEE_PROPERTY, consentee));
        for (Node node : search) {
            Consent consent = new Consent();
            consent.setConsentee(consentee);

            // all consent info is stored in the properties of the consent node
            Map<String, String> properties = node.getProperties();

            String consenter = properties.get(CONSENTER_PROPERTY);
            consent.setConsenter(consenter);

            String permsStr = properties.get(PERMISSIONS_PROPERTY);
            String nodesStr = properties.get(NODES_PROPERTY);

            if (permsStr == null) {
                continue;
            }

            OperationSet ops = new OperationSet(permsStr.split(","));
            consent.setPermissions(ops);

            if (!nodesStr.isEmpty()) {
                String[] pieces = nodesStr.split(",");
                for (String name : pieces) {
                    consent.addNode(graph.getNode(name));
                }
            }

            consent.setProhibitions(getProhibitions(consenter, consentee));

            consents.add(consent);
        }

        return consents;
    }

    /**
     * create an OA with the given parameters as properties
     * overwrite any existing policy
     *   - overwrite by getting the OA with prop
     *   - an existing consent is one with an OA labeled consenter=consenter & consentee=consentee
     *      - delete the UA and OA
     *
     *
     * @param consenter the target giving the consent (i.e. the patient). If someone is giving consent on the behalf of
     *                  another it's the person who the consent is being given on the behalf of
     * @param consentee the subject receiving the consent (i.e. the doctor)
     * @param permissions the permissions to give the subject
     * @param nodes the nodes to give consent on. Can be O or OA
     * @param prohibitions a set of containers that are prohibited grouped by similar permissions (i.e. read,write -> cont1, cont2)
     */
    public void giveConsent(String consenter, String consentee, OperationSet permissions, Set<String> nodes, Map<Set<String>, Set<String>> prohibitions) throws PMException {
        revokeConsent(consenter, consentee);

        // create the UA and OA
        // get the consenter consent group and container
        Node consentGroup = graph.getNode(UA, Node.toProperties(CONSENT_PROPERTY, consenter));
        Node consentContainer = graph.getNode(OA, Node.toProperties(CONSENT_PROPERTY, consenter));

        // create a UA and OA for this consent
        // prohibition string representation: read,write:cont1,cont2;read:cont3
        List<Prohibition> prohibitionList = new ArrayList<>();
        String prohibitionsStr = "";

        Map<Set<String>, Node> opsToProhibitionCont = new HashMap<>();
        for (Set<String> ops : prohibitions.keySet()) {
            // create an OA for all the conts
            Node node = graph.createNode("prohibition-consent-container-" + consentee + "-" + ops,
                    OA, Node.toProperties(CONSENTER_PROPERTY, consenter, CONSENTEE_PROPERTY, consentee), consentContainer.getName());
            opsToProhibitionCont.put(ops, node);
        }

        for (Set<String> ops : prohibitions.keySet()) {
            if (!prohibitionsStr.isEmpty()) {
                prohibitionsStr += ";";
            }
            Set<String> conts = prohibitions.get(ops);
            prohibitionsStr += String.join(",", ops) + ":" + String.join(",", conts);

            Node opsCont = opsToProhibitionCont.get(ops);

            // create prohibition object
            Prohibition prohibition = new Prohibition.Builder(getDenyName(consenter, consentee, new ArrayList<>(permissions), new ArrayList<>(conts)), consentee, new OperationSet(ops))
                    .setIntersection(false)
                    .addContainer(opsCont.getName(), false)
                    .build();
            for (String cont : conts) {
                // prohibition.addContainer(cont, false);
                graph.assign(cont, opsCont.getName());
            }

            prohibitionList.add(prohibition);
        }

        Node uaNode = graph.createNode(
                "consent-for-" + consentee + "-on-" + consenter + "_UA",
                UA,
                Node.toProperties(CONSENTEE_PROPERTY, consentee, CONSENTER_PROPERTY, consenter,
                        PERMISSIONS_PROPERTY, String.join(",", permissions), NODES_PROPERTY, String.join(",", nodes),
                        PROHIBITIONS_PROPERTY, prohibitionsStr),
                consentGroup.getName());

        Node oaNode = graph.createNode(
                "consent-for-" + consentee + "-on-" + consenter + "_OA",
                OA,
                Node.toProperties(CONSENTEE_PROPERTY, consentee, CONSENTER_PROPERTY, consenter,
                        PERMISSIONS_PROPERTY, String.join(",", permissions), NODES_PROPERTY, String.join(",", nodes),
                        PROHIBITIONS_PROPERTY, prohibitionsStr),
                consentContainer.getName());

        // associate the ua and oa with the permissions
        graph.associate(uaNode.getName(), oaNode.getName(), new OperationSet(permissions));

        // assign the consentee to the UA
        graph.assign(consentee, uaNode.getName());

        // assign all the nodes to the OA
        for (String node : nodes) {
            graph.assign(node, oaNode.getName());
        }

        // create prohibitions
        for (Prohibition prohibition : prohibitionList) {
            this.prohibitions.add(prohibition);
        }
    }

    public void revokeConsent(String consenter, String consentee) throws PMException {
        // delete the UA and OA with consenter and consentee props
        Set<Node> search = graph.search(null, Node.toProperties(CONSENTER_PROPERTY, consenter, CONSENTEE_PROPERTY, consentee));
        for (Node node : search) {
            graph.deleteNode(node.getName());
        }

        // delete any prohibitions that were apart of the consent
        Set<Prohibition> pros = getProhibitions(consenter, consentee);
        for (Prohibition pro : pros) {
            prohibitions.delete(pro.getName());
        }
    }

    private Set<Prohibition> getProhibitions(String consenter, String consentee) throws PMException {
        List<Prohibition> prohibitionsFor = prohibitions.getProhibitionsFor(consentee);
        Set<Prohibition> pros = new HashSet<>();
        for (Prohibition pro : prohibitionsFor) {
            if (pro.getName().startsWith("for-"+consenter+"-deny-"+consentee)) {
                pros.add(pro);
            }
        }

        return pros;
    }

    public static Obligation getObligation(UserContext userCtx) throws EVRException {
        String yaml =
                "label: consent obligation\n" +
                        "rules:\n" +
                        "  - label: consent rule\n" +
                        "    event:\n" +
                        "      subject:\n" +
                        "      operations:\n" +
                        "        - assign to\n" +
                        "      target:\n" +
                        "        policyElements:\n" +
                        "          - dac_users\n" +
                        "    response:\n" +
                        "      actions:\n" +
                        "        - function:\n" +
                        "            name: config_consent";
        return EVRParser.parse(userCtx.getUser(), yaml);
    }

    public static FunctionExecutor getFunction() {
        return new ConsentEVRFunction();
    }
}
