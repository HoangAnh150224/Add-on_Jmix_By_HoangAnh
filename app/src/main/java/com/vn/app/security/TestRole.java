package com.vn.app.security;

import io.jmix.security.role.annotation.ResourceRole;
import io.jmix.security.role.annotation.SpecificPolicy;
import io.jmix.securityflowui.role.annotation.MenuPolicy;
import io.jmix.securityflowui.role.annotation.ViewPolicy;

@ResourceRole(name = "test", code = TestRole.CODE)
public interface TestRole {
    String CODE = "test";

    @SpecificPolicy(resources = "*")
    void specific();

    @MenuPolicy(menuIds = "User.list")
    @ViewPolicy(viewIds = "User.list")
    void screens();
}