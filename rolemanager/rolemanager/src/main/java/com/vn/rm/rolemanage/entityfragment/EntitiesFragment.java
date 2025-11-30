package com.vn.rm.rolemanage.entityfragment;

import com.google.common.base.Strings;
import com.vaadin.flow.component.checkbox.Checkbox;
import com.vaadin.flow.component.grid.HeaderRow;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.data.renderer.LitRenderer;
import com.vn.rm.rolemanage.service.RoleManagerService;
import io.jmix.core.Metadata;
import io.jmix.core.MetadataTools;
import io.jmix.flowui.component.grid.DataGrid;
import io.jmix.flowui.fragment.Fragment;
import io.jmix.flowui.fragment.FragmentDescriptor;
import io.jmix.flowui.model.CollectionContainer;
import io.jmix.flowui.view.Subscribe;
import io.jmix.flowui.view.Target;
import io.jmix.flowui.view.ViewComponent;
import io.jmix.security.model.ResourcePolicyModel;
import io.jmix.securityflowui.view.resourcepolicy.AttributeResourceModel;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;

@FragmentDescriptor("entities-fragment.xml")
public class EntitiesFragment extends Fragment<VerticalLayout> {

    @ViewComponent
    private CollectionContainer<ResourcePolicyModel> resourcePoliciesDc;

    @ViewComponent
    private CollectionContainer<EntityMatrixRow> entityMatrixDc;
    @ViewComponent
    private DataGrid<EntityMatrixRow> entityMatrixTable;

    @ViewComponent
    private CollectionContainer<AttributeResourceModel> attrMatrixDc;
    @ViewComponent
    private DataGrid<AttributeResourceModel> attrMatrixTable;

    @ViewComponent
    private Span attrEntityLabel;

    @Autowired
    private RoleManagerService roleManagerService;

    @Autowired
    private Metadata metadata;

    @Autowired
    private MetadataTools metadataTools;

    // --- Biến kiểm tra Role ReadOnly ---
    private boolean isRoleReadOnly = false;

    // Headers Entity
    private Checkbox headerAllowAllCb;
    private Checkbox headerCreateCb;
    private Checkbox headerReadCb;
    private Checkbox headerUpdateCb;
    private Checkbox headerDeleteCb;

    // Headers Attribute
    private Checkbox headerAttrViewCb;
    private Checkbox headerAttrModifyCb;

    private boolean updatingHeaderFromRows = false;
    private boolean updatingAttrHeaderFromRows = false;

    // Cache chỉ dùng cho dữ liệu Attribute
    private final Map<String, List<AttributeResourceModel>> attrCache = new HashMap<>();

    // ========================================================================
    // Setter & External Logic
    // ========================================================================
    public void setRoleReadOnly(boolean readOnly) {
        this.isRoleReadOnly = readOnly;
        updateHeadersState();
        if (entityMatrixTable != null) entityMatrixTable.getDataProvider().refreshAll();
        if (attrMatrixTable != null) attrMatrixTable.getDataProvider().refreshAll();
    }

    private void updateHeadersState() {
        boolean enabled = !isRoleReadOnly;
        if (headerAllowAllCb != null) headerAllowAllCb.setEnabled(enabled);
        if (headerCreateCb != null) headerCreateCb.setEnabled(enabled);
        if (headerReadCb != null) headerReadCb.setEnabled(enabled);
        if (headerUpdateCb != null) headerUpdateCb.setEnabled(enabled);
        if (headerDeleteCb != null) headerDeleteCb.setEnabled(enabled);
    }

    // ========================================================================
    // Lifecycle
    // ========================================================================

    @Subscribe
    public void onReady(ReadyEvent event) {
        attrCache.clear();
        entityMatrixTable.setSelectionMode(DataGrid.SelectionMode.SINGLE);

        installMatrixColumns();
        installAttrColumns();
        initEntityHeader();
        initAttrHeader();

        if (entityMatrixDc.getItems().isEmpty()) {
            List<EntityMatrixRow> rows = roleManagerService.createMatrixEntity();
            entityMatrixDc.setItems(rows);
        }
        updateHeadersState();
    }

    @Subscribe(id = "entityMatrixDc", target = Target.DATA_CONTAINER)
    public void onEntityMatrixItemChange(CollectionContainer.ItemChangeEvent<EntityMatrixRow> e) {
        EntityMatrixRow row = e.getItem();
        if (row == null) {
            if (attrEntityLabel != null) attrEntityLabel.setText("");
            attrMatrixDc.setItems(Collections.emptyList());
            updateAttrHeaderState(true);
            return;
        }

        String cap = Optional.ofNullable(row.getEntityCaption()).orElse(row.getEntityName());
        if (attrEntityLabel != null) {
            attrEntityLabel.setText("Entity: " + cap + " (" + row.getEntityName() + ")");
        }

        loadAttributesForEntity(row.getEntityName());
    }

    public void initPolicies(Collection<ResourcePolicyModel> policies) {
        if (policies != null) {
            resourcePoliciesDc.setItems(new ArrayList<>(policies));
        } else {
            resourcePoliciesDc.setItems(Collections.emptyList());
        }

        if (entityMatrixDc.getItems().isEmpty()) {
            List<EntityMatrixRow> rows = roleManagerService.createMatrixEntity();
            entityMatrixDc.setItems(rows);
        }
        refreshMatrixFromPolicies();
    }

    private void refreshMatrixFromPolicies() {
        List<EntityMatrixRow> rows = new ArrayList<>(entityMatrixDc.getItems());
        Collection<ResourcePolicyModel> policies =
                Optional.ofNullable(resourcePoliciesDc.getItems()).orElseGet(List::of);

        attrCache.clear();

        roleManagerService.updateEntityMatrix(rows, policies, attrCache);

        entityMatrixDc.setItems(rows);
        updateHeaderAllowAllFromRows();

        attrMatrixDc.setItems(Collections.emptyList());
        if (attrEntityLabel != null) attrEntityLabel.setText("");
    }

    // ========================================================================
    // Logic: Load & Apply Attributes
    // ========================================================================

    private void loadAttributesForEntity(String entityName) {
        if (Strings.isNullOrEmpty(entityName) || "*".equals(entityName.trim()) || "All entities (*)".equals(entityName)) {
            if (attrEntityLabel != null) attrEntityLabel.setText("");
            attrMatrixDc.setItems(Collections.emptyList());
            updateAttrHeaderState(true);
            return;
        }

        if (attrEntityLabel != null) attrEntityLabel.setText("Entity: " + entityName);

        // Lấy từ cache hoặc load mới (Copy list để an toàn)
        List<AttributeResourceModel> rows = attrCache.computeIfAbsent(entityName, k -> {
            List<AttributeResourceModel> fromService = roleManagerService.buildAttrRowsForEntity(k);
            if (fromService == null) return new ArrayList<>();
            return new ArrayList<>(fromService);
        });


        attrMatrixDc.setItems(new ArrayList<>(rows));
        updateAttrHeaderState(false);
        updateAttrHeaderFromRows();
    }


    private void updateEntityAttributesSummary(String entityName) {
        // Lấy đúng danh sách attribute của Entity cần update từ Cache
        List<AttributeResourceModel> attributesForThisEntity = attrCache.get(entityName);

        // Nếu chưa có trong cache thì load mới (tránh null pointer)
        if (attributesForThisEntity == null) {
            attributesForThisEntity = roleManagerService.buildAttrRowsForEntity(entityName);
            attrCache.put(entityName, attributesForThisEntity);
        }

        // Truyền đúng list attribute của entity đó vào Service
        // TUYỆT ĐỐI KHÔNG DÙNG attrMatrixDc.getItems() VÌ NÓ CÓ THỂ ĐANG SHOW ENTITY KHÁC
        roleManagerService.updateEntityAttributesSummary(
                entityName,
                entityMatrixDc.getItems(),
                attributesForThisEntity, // <--- Đã sửa chỗ này
                attrCache
        );
    }

    private void updateAttrHeaderState(boolean disabled) {
        boolean canEdit = !disabled && !isRoleReadOnly;
        if (headerAttrModifyCb != null) headerAttrModifyCb.setEnabled(canEdit);
        if (headerAttrViewCb != null) headerAttrViewCb.setEnabled(canEdit);
    }

    private void resetAllAttributesFlags() {
        attrCache.values().forEach(list -> {
            for (AttributeResourceModel a : list) {
                a.setView(false);
                a.setModify(false);
            }
        });

        List<AttributeResourceModel> currentAttrs = attrMatrixDc.getItems();
        if (!currentAttrs.isEmpty()) {
            attrMatrixTable.getDataProvider().refreshAll();
        }

        List<EntityMatrixRow> entities = entityMatrixDc.getItems();
        for (EntityMatrixRow r : entities) r.setAttributes(null);
        entityMatrixTable.getDataProvider().refreshAll();

        if (headerAttrViewCb != null) headerAttrViewCb.setValue(false);
        if (headerAttrModifyCb != null) headerAttrModifyCb.setValue(false);
    }

    // ========================================================================
    // Entity Matrix Columns
    // ========================================================================

    private void installMatrixColumns() {
        DataGrid.Column<EntityMatrixRow> allowAllCol = entityMatrixTable.getColumnByKey("allowAllCol");
        if (allowAllCol != null) {
            String html = "<vaadin-checkbox " +
                    "?checked='${item.checked}' " +
                    ".indeterminate='${item.indet}' " +
                    "?disabled='${item.disabled}' " +
                    "@change='${handleChange}'></vaadin-checkbox>";

            allowAllCol.setRenderer(LitRenderer.<EntityMatrixRow>of(html)
                    .withProperty("checked", row -> T(row.getAllowAll()))
                    .withProperty("disabled", row -> isRoleReadOnly)
                    .withProperty("indet", row -> {
                        boolean isAll = T(row.getAllowAll());
                        boolean hasAny = T(row.getCanCreate()) || T(row.getCanRead()) ||
                                T(row.getCanUpdate()) || T(row.getCanDelete());
                        return !isAll && hasAny;
                    })
                    .withFunction("handleChange", row -> {
                        boolean newVal = !T(row.getAllowAll());
                        row.setAllowAll(newVal);
                        row.setCanCreate(newVal);
                        row.setCanRead(newVal);
                        row.setCanUpdate(newVal);
                        row.setCanDelete(newVal);

//                        applyAllowAllToAttributes(row.getEntityName(), newVal);
                        entityMatrixTable.getDataProvider().refreshItem(row);
                        updateHeaderAllowAllFromRows();
                    }));
        }

        installPermissionColumn("createCol", EntityMatrixRow::getCanCreate, EntityMatrixRow::setCanCreate);
        installPermissionColumn("readCol", EntityMatrixRow::getCanRead, EntityMatrixRow::setCanRead);
        installPermissionColumn("updateCol", EntityMatrixRow::getCanUpdate, EntityMatrixRow::setCanUpdate);
        installPermissionColumn("deleteCol", EntityMatrixRow::getCanDelete, EntityMatrixRow::setCanDelete);

        DataGrid.Column<EntityMatrixRow> attrCol = entityMatrixTable.getColumnByKey("attributesCol");
        if (attrCol != null) {
            attrCol.setRenderer(LitRenderer.<EntityMatrixRow>of(
                            "<span style='font-size: var(--lumo-font-size-s);'>${item.text}</span>")
                    .withProperty("text", row -> Strings.nullToEmpty(row.getAttributes())));
        }
    }

    private void installPermissionColumn(String colId, Function<EntityMatrixRow, Boolean> getter, BiConsumer<EntityMatrixRow, Boolean> setter) {
        DataGrid.Column<EntityMatrixRow> col = entityMatrixTable.getColumnByKey(colId);
        if (col != null) {
            String html = "<vaadin-checkbox " +
                    "?checked='${item.checked}' " +
                    "?disabled='${item.disabled}' " +
                    "@change='${handleChange}'></vaadin-checkbox>";

            col.setRenderer(LitRenderer.<EntityMatrixRow>of(html)
                    .withProperty("checked", row -> T(getter.apply(row)))
                    .withProperty("disabled", row -> isRoleReadOnly)
                    .withFunction("handleChange", row -> {
                        boolean newVal = !T(getter.apply(row));
                        setter.accept(row, newVal);
                        roleManagerService.syncAllowAll(row);
                        entityMatrixTable.getDataProvider().refreshItem(row);
                        updateHeaderAllowAllFromRows();
                    }));
        }
    }

    // ========================================================================
    // Attribute Matrix Columns
    // ========================================================================

    private void installAttrColumns() {
        DataGrid.Column<AttributeResourceModel> nameCol = attrMatrixTable.getColumnByKey("attribute");
        if (nameCol != null) {
            nameCol.setRenderer(LitRenderer.<AttributeResourceModel>of("<span>${item.name}</span>")
                    .withProperty("name", row -> Strings.nullToEmpty(row.getName())));
        }

        installAttrCheckboxColumn("viewCol", AttributeResourceModel::getView, (row, v) -> {
            row.setView(v);
            if (v) row.setModify(false);
        });

        installAttrCheckboxColumn("modifyCol", AttributeResourceModel::getModify, (row, v) -> {
            row.setModify(v);
            if (v) row.setView(false);
        });
    }

    private void installAttrCheckboxColumn(String colId, Function<AttributeResourceModel, Boolean> getter, BiConsumer<AttributeResourceModel, Boolean> setter) {
        DataGrid.Column<AttributeResourceModel> col = attrMatrixTable.getColumnByKey(colId);
        if (col != null) {
            String html = "<vaadin-checkbox " +
                    "?checked='${item.checked}' " +
                    "?disabled='${item.disabled}' " +
                    "@change='${handleChange}'></vaadin-checkbox>";

            col.setRenderer(LitRenderer.<AttributeResourceModel>of(html)
                    .withProperty("checked", row -> T(getter.apply(row)))
                    .withProperty("disabled", row -> isRoleReadOnly)
                    .withFunction("handleChange", row -> {
                        boolean newVal = !T(getter.apply(row));
                        setter.accept(row, newVal);

                        // Refresh dòng hiện tại của bảng Attribute
                        attrMatrixTable.getDataProvider().refreshItem(row);
                        updateAttrHeaderFromRows();

                        // CẬP NHẬT NGAY BẢNG ENTITY
                        EntityMatrixRow currentEntity = entityMatrixDc.getItemOrNull();
                        if (currentEntity != null) {
                            // Đồng bộ list hiện tại vào cache để tính toán đúng
                            List<AttributeResourceModel> currentItems = attrMatrixDc.getItems();
                            attrCache.put(currentEntity.getEntityName(), new ArrayList<>(currentItems));

                            updateEntityAttributesSummary(currentEntity.getEntityName());
                            entityMatrixTable.getDataProvider().refreshItem(currentEntity);
                        }
                    }));
        }
    }
    // ========================================================================
    // Header Components
    // ========================================================================

    protected void initEntityHeader() {
        HeaderRow row = entityMatrixTable.appendHeaderRow();
        DataGrid.Column<EntityMatrixRow> entityCol = entityMatrixTable.getColumns().isEmpty() ? null : entityMatrixTable.getColumns().get(0);
        if (entityCol != null) row.getCell(entityCol).setText("All entities (*)");

        // --- XỬ LÝ CHECKBOX: ALL ENTITIES ---
        headerAllowAllCb = createHeaderCheckbox(row, "allowAllCol", (r, v) -> {
            // Logic này chỉ dùng cho từng dòng lẻ (nếu cần),
            // còn logic chính của header nằm ở listener bên dưới.
            if (isRoleReadOnly) return;
            r.setAllowAll(v);
            r.setCanCreate(v);
            r.setCanRead(v);
            r.setCanUpdate(v);
            r.setCanDelete(v);
        });

        if (headerAllowAllCb != null) {
            headerAllowAllCb.addValueChangeListener(e -> {
                if (updatingHeaderFromRows || !e.isFromClient()) return;
                boolean v = Boolean.TRUE.equals(e.getValue());

                List<EntityMatrixRow> items = new ArrayList<>(entityMatrixDc.getItems());

                // Duyệt qua tất cả Entity để cập nhật
                for (EntityMatrixRow r : items) {
                    if (!isRoleReadOnly) {
                        // 1. Cập nhật quyền CRUD (Entity)
                        r.setAllowAll(v);
                        r.setCanCreate(v);
                        r.setCanRead(v);
                        r.setCanUpdate(v);
                        r.setCanDelete(v);

                        // 2. Cập nhật quyền ATTRIBUTE (MỚI THÊM)
                        if (v) {
                            // Nếu đang tích chọn -> Set Modify All cho Attribute của entity này

                            // Lấy list attribute từ cache hoặc load mới nếu chưa có
                            List<AttributeResourceModel> attrs = attrCache.computeIfAbsent(r.getEntityName(),
                                    k -> roleManagerService.buildAttrRowsForEntity(k));

                            // Set Modify = true cho tất cả attribute
                            for (AttributeResourceModel a : attrs) {
                                a.setModify(true);
                                a.setView(false);
                            }

                            // Cập nhật lại chuỗi hiển thị "*" cho dòng entity này
                            roleManagerService.updateEntityAttributesSummary(r.getEntityName(), items, attrs, attrCache);
                        }
                    }
                }

                // 3. Nếu bỏ chọn (Uncheck All) -> Reset toàn bộ attribute về false
                if (!v) {
                    resetAllAttributesFlags();
                }

                // 4. Refresh lại bảng Entity để thấy dấu "*"
                entityMatrixTable.getDataProvider().refreshAll();

                // 5. Nếu đang chọn 1 dòng nào đó, refresh luôn bảng Attribute bên phải
                EntityMatrixRow current = entityMatrixDc.getItemOrNull();
                if (current != null) {
                    loadAttributesForEntity(current.getEntityName());
                }

                updateHeaderAllowAllFromRows();
            });
        }

        // --- CÁC CHECKBOX HEADER KHÁC (Giữ nguyên) ---
        headerCreateCb = createHeaderCheckbox(row, "createCol", (r, v) -> {
            if (isRoleReadOnly) return;
            r.setCanCreate(v);
            roleManagerService.syncAllowAll(r);
        });
        headerReadCb = createHeaderCheckbox(row, "readCol", (r, v) -> {
            if (isRoleReadOnly) return;
            r.setCanRead(v);
            roleManagerService.syncAllowAll(r);
        });
        headerUpdateCb = createHeaderCheckbox(row, "updateCol", (r, v) -> {
            if (isRoleReadOnly) return;
            r.setCanUpdate(v);
            roleManagerService.syncAllowAll(r);
        });
        headerDeleteCb = createHeaderCheckbox(row, "deleteCol", (r, v) -> {
            if (isRoleReadOnly) return;
            r.setCanDelete(v);
            roleManagerService.syncAllowAll(r);
        });

        updateHeadersState();
    }
    private Checkbox createHeaderCheckbox(HeaderRow headerRow, String colKey, BiConsumer<EntityMatrixRow, Boolean> logic) {
        DataGrid.Column<EntityMatrixRow> col = entityMatrixTable.getColumnByKey(colKey);
        if (col == null) return null;
        Checkbox cb = new Checkbox();

        if (!"allowAllCol".equals(colKey)) {
            cb.addValueChangeListener(e -> {
                if (updatingHeaderFromRows || !e.isFromClient()) return;
                boolean v = Boolean.TRUE.equals(e.getValue());
                List<EntityMatrixRow> items = new ArrayList<>(entityMatrixDc.getItems());
                for (EntityMatrixRow r : items) logic.accept(r, v);
                entityMatrixTable.getDataProvider().refreshAll();
                updateHeaderAllowAllFromRows();
            });
        }

        headerRow.getCell(col).setComponent(cb);
        return cb;
    }

    private void updateHeaderAllowAllFromRows() {
        if (headerAllowAllCb == null) return;
        updatingHeaderFromRows = true;
        try {
            List<EntityMatrixRow> items = entityMatrixDc.getItems();
            if (items == null || items.isEmpty()) {
                setHeadersValue(false, false, false, false, false);
                return;
            }
            boolean allC = items.stream().allMatch(r -> T(r.getCanCreate()));
            boolean allR = items.stream().allMatch(r -> T(r.getCanRead()));
            boolean allU = items.stream().allMatch(r -> T(r.getCanUpdate()));
            boolean allD = items.stream().allMatch(r -> T(r.getCanDelete()));
            boolean allA = items.stream().allMatch(r -> T(r.getAllowAll()));
            setHeadersValue(allA, allC, allR, allU, allD);
        } finally {
            updatingHeaderFromRows = false;
        }
    }

    private void setHeadersValue(boolean all, boolean c, boolean r, boolean u, boolean d) {
        if (headerAllowAllCb != null) headerAllowAllCb.setValue(all);
        if (headerCreateCb != null) headerCreateCb.setValue(c);
        if (headerReadCb != null) headerReadCb.setValue(r);
        if (headerUpdateCb != null) headerUpdateCb.setValue(u);
        if (headerDeleteCb != null) headerDeleteCb.setValue(d);
    }

    private void initAttrHeader() {
        HeaderRow row = attrMatrixTable.appendHeaderRow();
        DataGrid.Column<AttributeResourceModel> attrCol = attrMatrixTable.getColumnByKey("name");
        DataGrid.Column<AttributeResourceModel> viewCol = attrMatrixTable.getColumnByKey("viewCol");
        DataGrid.Column<AttributeResourceModel> modifyCol = attrMatrixTable.getColumnByKey("modifyCol");
        if (attrCol != null) row.getCell(attrCol).setText("All attributes (*)");

        // --- Checkbox Header: VIEW ---
        if (viewCol != null) {
            headerAttrViewCb = new Checkbox();
            headerAttrViewCb.addValueChangeListener(e -> {
                if (updatingAttrHeaderFromRows || !e.isFromClient()) return;
                boolean v = Boolean.TRUE.equals(e.getValue());

                // 1. Lấy danh sách đang hiển thị và cập nhật giá trị
                List<AttributeResourceModel> items = attrMatrixDc.getItems();
                items.forEach(r -> {
                    r.setView(v);
                    if (v) r.setModify(false);
                });

                // 2. Refresh bảng Attribute (Bên phải)
                attrMatrixTable.getDataProvider().refreshAll();
                updateAttrHeaderFromRows();

                // 3. CẬP NHẬT NGAY BẢNG ENTITY (Bên trái)
                EntityMatrixRow currentEntity = entityMatrixDc.getItemOrNull();
                if (currentEntity != null) {
                    // Cực kỳ quan trọng: Đồng bộ list items vừa sửa vào cache
                    attrCache.put(currentEntity.getEntityName(), new ArrayList<>(items));

                    // Tính toán lại chuỗi hiển thị (ví dụ từ "" thành "*")
                    updateEntityAttributesSummary(currentEntity.getEntityName());

                    // Ép bảng Entity vẽ lại dòng này để hiện dấu "*"
                    entityMatrixTable.getDataProvider().refreshItem(currentEntity);
                }
            });
            row.getCell(viewCol).setComponent(headerAttrViewCb);
        }

        // --- Checkbox Header: MODIFY ---
        if (modifyCol != null) {
            headerAttrModifyCb = new Checkbox();
            headerAttrModifyCb.addValueChangeListener(e -> {
                if (updatingAttrHeaderFromRows || !e.isFromClient()) return;
                boolean v = Boolean.TRUE.equals(e.getValue());

                // 1. Lấy danh sách đang hiển thị và cập nhật giá trị
                List<AttributeResourceModel> items = attrMatrixDc.getItems();
                items.forEach(r -> {
                    r.setModify(v);
                    if (v) r.setView(false);
                });

                // 2. Refresh bảng Attribute (Bên phải)
                attrMatrixTable.getDataProvider().refreshAll();
                updateAttrHeaderFromRows();

                // 3. CẬP NHẬT NGAY BẢNG ENTITY (Bên trái)
                EntityMatrixRow currentEntity = entityMatrixDc.getItemOrNull();
                if (currentEntity != null) {
                    // Cực kỳ quan trọng: Đồng bộ list items vừa sửa vào cache
                    attrCache.put(currentEntity.getEntityName(), new ArrayList<>(items));

                    // Tính toán lại chuỗi hiển thị (ví dụ từ "" thành "*")
                    updateEntityAttributesSummary(currentEntity.getEntityName());

                    // Ép bảng Entity vẽ lại dòng này để hiện dấu "*"
                    entityMatrixTable.getDataProvider().refreshItem(currentEntity);
                }
            });
            row.getCell(modifyCol).setComponent(headerAttrModifyCb);
        }
        updateAttrHeaderFromRows();
    }

    private void updateAttrHeaderFromRows() {
        if (headerAttrViewCb == null && headerAttrModifyCb == null) return;
        updatingAttrHeaderFromRows = true;
        try {
            List<AttributeResourceModel> items = attrMatrixDc.getItems();
            if (items == null || items.isEmpty()) {
                if (headerAttrViewCb != null) headerAttrViewCb.setValue(false);
                if (headerAttrModifyCb != null) headerAttrModifyCb.setValue(false);
                return;
            }
            boolean allV = items.stream().allMatch(r -> T(r.getView()));
            boolean allM = items.stream().allMatch(r -> T(r.getModify()));
            if (headerAttrViewCb != null) headerAttrViewCb.setValue(allV);
            if (headerAttrModifyCb != null) headerAttrModifyCb.setValue(allM);
        } finally {
            updatingAttrHeaderFromRows = false;
        }
    }

    public List<ResourcePolicyModel> buildPoliciesFromMatrix() {
        return roleManagerService.buildPoliciesFromMatrix(new ArrayList<>(entityMatrixDc.getItems()), attrCache);
    }

    private static boolean T(Boolean b) {
        return Boolean.TRUE.equals(b);
    }
}