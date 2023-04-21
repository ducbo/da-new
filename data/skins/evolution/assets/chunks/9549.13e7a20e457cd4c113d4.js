"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[9549],{"./js/api/commands/user/handlers.js":function(x,l,r){r.r(l),r.d(l,{createHandler:function(){return c},deleteHandlerExtension:function(){return p},deleteHandlers:function(){return u},getHandlers:function(){return d},getSystemHandlers:function(){return a}});var o=r("./js/api/command/index.js");const d=o.Z.get({id:"HANDLERS",url:"/CMD_HANDLERS",domain:!0,pagination:!0,after:i=>i.flow(m=>({rows:m}),i.processTableInfo("rows"),i.mapProps({rows:i.toArray}))}),a=d.extend({id:"SYSTEM_HANDLERS",params:{action:"system"}}),c=o.Z.post({url:"/CMD_HANDLERS",params:{action:"add"},domain:!0,schema:{name:o.Z.REQUIRED_STRING,extension:o.Z.REQUIRED_STRING}}),u=o.Z.select({url:"/CMD_HANDLERS",params:{action:"multiple",button:"type"},domain:!0}),p=u.extend({params:{button:"extension"},schema:{extension:o.Z.REQUIRED_STRING}})},"./js/pages/user/handlers/index.vue":function(x,l,r){r.r(l),r.d(l,{default:function(){return m}});var o=function(){var e=this,t=e._self._c;return t("app-page",{attrs:{actions:[{label:e.$gettext("Create Handler"),handler:e.$dialog("CREATE_HANDLER_DIALOG").open,icon:"#plus-fill"},{label:e.$gettext("System Apache Handlers"),name:"user/handlers/system",icon:"#settings"}]},scopedSlots:e._u([{key:"default",fn:function(){return[t("app-page-section",[t("ui-api-table",e._b({on:{"action:deleteHandler":function(s){e.$dialog("DELETE_HANDLERS_DIALOG").open()},"action:deleteExtension":function(s){e.$dialog("DELETE_EXTENSION_DIALOG").open()}},model:{value:e.select,callback:function(s){e.select=s},expression:"select"}},"ui-api-table",{command:e.$commands.getHandlers,rowID:"handler",columns:{handler:e.$gettext("Handler"),extensions:e.$gettext("Extensions")},actions:{deleteHandler:e.$gettext("Delete Handler"),deleteExtension:e.$gettext("Delete Extension")},equalWidthLayout:!0},!1))],1),e._v(" "),t("ui-dialog",{attrs:{id:"CREATE_HANDLER_DIALOG",theme:"safe",title:e.$gettext("Add New Apache Handler")},scopedSlots:e._u([{key:"content",fn:function(){return[t("ui-form-element",{attrs:{group:"createHandler",validators:{required:!0,maxLength:50}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Name"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.add.name,callback:function(s){e.$set(e.add,"name",s)},expression:"add.name"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{group:"createHandler",validators:{required:!0,notEmpty:s=>!s||!!s.trim(),validateExtension:e.validateExtension,maxLength:10}},scopedSlots:e._u([{key:"title",fn:function(){return[e._v(e._s(e.$gettext("Extension")))]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.add.extension,callback:function(s){e.$set(e.add,"extension",s)},expression:"add.extension"}})]},proxy:!0},{key:"error:notEmpty",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Required field"))}})]},proxy:!0},{key:"error:validateExtension",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Handler for such extension already exists"))}})]},proxy:!0}])})]},proxy:!0},{key:"buttons",fn:function(){return[t("ui-button",{attrs:{theme:"safe","validate-group":"createHandler"},on:{click:e.createHandler}},[t("span",{domProps:{textContent:e._s(e.$gettext("Create"))}})])]},proxy:!0}])}),e._v(" "),t("ui-dialog-delete-items",{attrs:{id:"DELETE_HANDLERS_DIALOG",subject:e.$ngettext("handler","handlers",e.select.length)},on:{"click:confirm":e.deleteHandlers}}),e._v(" "),t("ui-dialog",{attrs:{id:"DELETE_EXTENSION_DIALOG",theme:"danger",title:e.$gettext("Delete Extension")},on:{"dialog:open":e.initDel},scopedSlots:e._u([{key:"content",fn:function(){return[t("ui-form-element",{attrs:{group:"deleteExtension",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Extension:"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-select",{attrs:{options:e.checkedExtensions},model:{value:e.del.extension,callback:function(s){e.$set(e.del,"extension",s)},expression:"del.extension"}})]},proxy:!0}])})]},proxy:!0},{key:"buttons",fn:function(){return[t("ui-button",{attrs:{theme:"danger","validate-group":"deleteExtension"},on:{click:e.deleteExtensions}},[t("span",{domProps:{textContent:e._s(e.$gettext("Delete"))}})])]},proxy:!0}])})]},proxy:!0}])})},d=[],a=r("./js/api/commands/user/handlers.js"),c={preload:[a.getHandlers,a.getSystemHandlers],api:[{command:a.getHandlers,bind:"handlers"},{command:a.getSystemHandlers,bind:"systemHandlers"}],commands:a,data:()=>({select:[],add:{name:"",extension:""},del:{extension:""}}),computed:{checkedExtensions(){return this.$api.handlers.rows.filter(n=>this.select.includes(n.handler)).map(n=>n.extensions.split(" ")).reduce((n,e)=>n.concat(e),[]).filter(n=>!!n)},handlersList(){return[...this.$api.handlers.rows.map(n=>n.handler),...this.$api.systemHandlers.rows.map(n=>n.handler)]},extensionsList(){return[...this.$api.handlers.rows.map(n=>n.extensions),...this.$api.systemHandlers.rows.map(n=>n.extensions)]}},watch:{$domain(){this.reloadTable()}},methods:{reloadTable(){this.$reloadApiTable(),Object.assign(this.$data,this.$options.data.apply(this))},createHandler(){a.createHandler({name:this.add.name.trim(),extension:this.add.extension.trim()}).then(this.reloadTable).then(()=>{Object.assign(this.$data,this.$options.data.apply(this))})},deleteHandlers(){a.deleteHandlers({select:this.select}).then(this.reloadTable).then(()=>{Object.assign(this.$data,this.$options.data.apply(this))})},deleteExtensions(){a.deleteHandlerExtension({select:this.select,extension:this.del.extension}).then(this.reloadTable).then(()=>{Object.assign(this.$data,this.$options.data.apply(this))})},validateExtension(n){return n?!this.extensionsList.includes(n):!0},initDel(){[this.del.extension]=this.checkedExtensions}}},u=c,p=r("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),i=(0,p.Z)(u,o,d,!1,null,null,null),m=i.exports}}]);