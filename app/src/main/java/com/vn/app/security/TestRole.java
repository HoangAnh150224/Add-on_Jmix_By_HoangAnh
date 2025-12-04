package com.vn.app.security;

import io.jmix.security.role.annotation.ResourceRole;
import io.jmix.security.role.annotation.SpecificPolicy;

@ResourceRole(name = "test", code = TestRole.CODE)
public interface TestRole {
    String CODE = "test";

    @SpecificPolicy(resources = {"datatools.showEntityInfo", "ui.genericfilter.modifyJpqlCondition", "ui.genericfilter.modifyConfiguration", "ui.loginToUi", "ui.genericfilter.modifyGlobalConfiguration", "ui.showExceptionDetails"})
    void specific();
}