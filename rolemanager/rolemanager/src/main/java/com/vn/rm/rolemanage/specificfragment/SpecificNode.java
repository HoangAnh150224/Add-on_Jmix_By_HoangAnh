package com.vn.rm.rolemanage.specificfragment;

import io.jmix.core.metamodel.annotation.JmixEntity;

import java.util.ArrayList;
import java.util.List;

@JmixEntity(name = "rm_SpecificNode")
public class SpecificNode {

    private String name;
    private Boolean group;
    private Boolean annotated;
    private String effect;
    private Boolean allow;
    private Boolean deny;

    private SpecificNode parent;
    private List<SpecificNode> children = new ArrayList<>();

    public SpecificNode() {}

    public SpecificNode(String name, Boolean group) {
        this.name = name;
        this.group = group;
    }

    public String getName() { return name; }
    public Boolean getGroup() { return group; }
    public boolean isLeaf() { return !Boolean.TRUE.equals(group); }

    public SpecificNode getParent() { return parent; }
    public void setParent(SpecificNode parent) { this.parent = parent; }

    public List<SpecificNode> getChildren() { return children; }
    public void setChildren(List<SpecificNode> children) { this.children = children; }

    public Boolean getAnnotated() { return annotated; }
    public void setAnnotated(Boolean annotated) { this.annotated = annotated; }

    public String getEffect() { return effect; }
    public void setEffect(String effect) { this.effect = effect; }

    public Boolean getAllow() { return allow; }
    public void setAllow(Boolean allow) { this.allow = allow; }

    public Boolean getDeny() { return deny; }
    public void setDeny(Boolean deny) { this.deny = deny; }
}
