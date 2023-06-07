package com.aidl.myutils.json;

/**
 * layout节点的字段,第三层
 */
public class TypeListBean {
    String icon;    //"icon_scene_07"
    String id;  //"750"
    String name;    //"手动场景"

    public String getIcon() {
        return icon;
    }

    public void setIcon(String icon) {
        this.icon = icon;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    String type;    //"scene"
}
