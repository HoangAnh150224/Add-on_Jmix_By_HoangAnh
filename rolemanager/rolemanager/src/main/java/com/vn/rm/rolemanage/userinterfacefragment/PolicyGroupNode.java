package com.vn.rm.rolemanage.userinterfacefragment;

import io.jmix.core.metamodel.annotation.JmixEntity;

import java.util.ArrayList;
import java.util.List;

@JmixEntity(name = "rm_PolicyGroupNode")
public class PolicyGroupNode {

    private String name;
    private Boolean group;
    private String type;
    private String resource;
    private String action;
    private String effect; // ALLOW | DENY | null
    private String meta;

    private Boolean allow;
    private Boolean deny;

    private Boolean denyDefault = false;
    private Boolean annotated = false;  // <-- BẠN XOÁ MẤT

    private PolicyGroupNode parent;
    private List<PolicyGroupNode> children = new ArrayList<>();

    public PolicyGroupNode(String name, Boolean group) {
        this.name = name;
        this.group = group;
    }


    public Boolean getAnnotated() { return annotated; }
    public void setAnnotated(Boolean annotated) { this.annotated = annotated; }
    public String getName() { return name; }
    public Boolean getGroup() { return group; }
    public String getType() { return type; }
    public String getResource() { return resource; }
    public String getAction() { return action; }
    public String getEffect() { return effect; }
    public String getMeta() { return meta; }
    public Boolean getAllow() { return allow; }
    public Boolean getDeny() { return deny; }
    public Boolean isDenyDefault() { return denyDefault; }

    public void setName(String name) { this.name = name; }
    public void setGroup(Boolean group) { this.group = group; }
    public void setType(String type) { this.type = type; }
    public void setResource(String resource) { this.resource = resource; }
    public void setAction(String action) { this.action = action; }
    public void setEffect(String effect) { this.effect = effect; }
    public void setMeta(String meta) { this.meta = meta; }
    public void setAllow(Boolean allow) { this.allow = allow; }
    public void setDeny(Boolean deny) { this.deny = deny; }
    public void setDenyDefault(Boolean denyDefault) { this.denyDefault = denyDefault; }

    public PolicyGroupNode getParent() { return parent; }
    public void setParent(PolicyGroupNode parent) { this.parent = parent; }

    public List<PolicyGroupNode> getChildren() { return children; }
    public void setChildren(List<PolicyGroupNode> children) { this.children = children; }

    public Boolean isLeaf() { return !group; }

    public void resetState() {
        // ✔ KHÔNG được deny
        if (Boolean.TRUE.equals(annotated)) {
            // Annotated → ALLOW
            this.effect = "ALLOW";
            this.allow = true;
        } else {
            // Không annotated → TRẠNG THÁI TRỐNG (neutral)
            this.effect = null;
            this.allow = false;
        }
        this.deny = false;
    }
}
