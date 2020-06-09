package gov.nist.csd.pm.policies.dac.consent.model;

import java.util.List;

public class ConsentRequest {

    private String requester;
    private String user;
    private List<String> permissions;

    public String getRequester() {
        return requester;
    }

    public void setRequester(String requester) {
        this.requester = requester;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public List<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
    }
}
