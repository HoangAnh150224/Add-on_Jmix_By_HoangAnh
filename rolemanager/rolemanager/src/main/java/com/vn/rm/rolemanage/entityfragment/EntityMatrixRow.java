package com.vn.rm.rolemanage.entityfragment;

import io.jmix.core.entity.annotation.JmixGeneratedValue;
import io.jmix.core.entity.annotation.JmixId;
import io.jmix.core.metamodel.annotation.JmixEntity;

import java.util.UUID;

@JmixEntity(name = "rm_EntityMatrixRow")
public class EntityMatrixRow {
    @JmixGeneratedValue
    @JmixId
    private UUID id;
    private String entityName;
    private String entityCaption;
    private Boolean allowAll   = Boolean.FALSE;
    private Boolean canCreate  = Boolean.FALSE;
    private Boolean canRead    = Boolean.FALSE;
    private Boolean canUpdate  = Boolean.FALSE;
    private Boolean canDelete  = Boolean.FALSE;
    private String attributes;



    public String getAttributes() {
        return attributes;
    }
    public void setAttributes(String attributes) {
        this.attributes = attributes;
    }
    public Boolean getCanDelete() {
        return canDelete;
    }
    public void setCanDelete(Boolean canDelete) {
        this.canDelete = canDelete;
    }
    public Boolean getCanUpdate() {
        return canUpdate;
    }
    public void setCanUpdate(Boolean canUpdate) {
        this.canUpdate = canUpdate;
    }
    public Boolean getCanRead() {
        return canRead;
    }
    public void setCanRead(Boolean canRead) {
        this.canRead = canRead;
    }
    public Boolean getCanCreate() {
        return canCreate;
    }
    public void setCanCreate(Boolean canCreate) {
        this.canCreate = canCreate;
    }
    public Boolean getAllowAll() {
        return allowAll;
    }
    public void setAllowAll(Boolean allowAll) {
        this.allowAll = allowAll;
    }
    public String getEntityCaption() {
        return entityCaption;
    }
    public void setEntityCaption(String entityCaption) {
        this.entityCaption = entityCaption;
    }
    public String getEntityName() {
        return entityName;
    }
    public void setEntityName(String entityName) {
        this.entityName = entityName;
    }
    public UUID getId() {
        return id;
    }
    public void setId(UUID id) {
        this.id = id;
    }

}