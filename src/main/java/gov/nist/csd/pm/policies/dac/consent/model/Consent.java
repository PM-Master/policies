package gov.nist.csd.pm.policies.dac.consent.model;

import gov.nist.csd.pm.operations.OperationSet;
import gov.nist.csd.pm.pip.graph.model.nodes.Node;
import gov.nist.csd.pm.pip.prohibitions.model.Prohibition;

import java.util.HashSet;
import java.util.Set;

public class Consent {

    private String creator;
    private String consenter;
    private String consentee;
    private OperationSet permissions;
    private Set<Node> nodes;
    private Set<Prohibition> prohibitions;

    public Consent() {
        permissions = new OperationSet();
        nodes = new HashSet<>();
        prohibitions = new HashSet<>();
    }

    public String getCreator() {
        return creator;
    }

    public void setCreator(String creator) {
        this.creator = creator;
    }

    public String getConsenter() {
        return consenter;
    }

    public void setConsenter(String consenter) {
        this.consenter = consenter;
    }

    public String getConsentee() {
        return consentee;
    }

    public void setConsentee(String consentee) {
        this.consentee = consentee;
    }

    public OperationSet getPermissions() {
        return permissions;
    }

    public void setPermissions(OperationSet permissions) {
        this.permissions = permissions;
    }

    public Set<Node> getNodes() {
        return nodes;
    }

    public void setNodes(Set<Node> nodes) {
        this.nodes = nodes;
    }

    public void addNode(Node node) {
        this.nodes.add(node);
    }

    public Set<Prohibition> getProhibitions() {
        return prohibitions;
    }

    public void setProhibitions(Set<Prohibition> prohibitions) {
        this.prohibitions = prohibitions;
    }

    public void addProhibition(Prohibition prohibition) {
        this.prohibitions.add(prohibition);
    }
}
