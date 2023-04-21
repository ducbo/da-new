"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[1552],{"./js/api/commands/reseller/skins.js":function(S,d,l){l.d(d,{$Y:function(){return p},UF:function(){return m},br:function(){return i},eD:function(){return k},v0:function(){return _}});var o=l("./js/api/command/index.js");const r="/CMD_SKINS",p=o.Z.get({id:"SKINS",url:r,response:[],after:()=>n=>Object.keys(n.full_list).map(a=>({skin:a,path:n.full_list[a],canLogo:typeof n.can_logo[a]!="undefined",owner:n.skin_owners[a]}))}),i=o.Z.select({url:r,schema:{apply_as:{type:String,default:"reseller",validator:n=>["reseller","all"].includes(n)}},before:({apply_as:n})=>({apply_as:null,[n]:!0})}),_=o.Z.select({url:r,params:{global_docsroot:!0,json:!0}}),k=o.Z.select({url:r,params:{delete:!0}}),m=o.Z.post({url:r,params:{action:"upload",MAX_FILE_SIZE:"10485760"},schema:{name:o.Z.REQUIRED_STRING,server:o.Z.REQUIRED_BOOL,file:{type:File,required:!0}},fileTransfer:!0,continous:!0}),c=n=>a=>({custom:a[`HAS_CUSTOM_${n.toUpperCase()}_TOKEN`]==="1",token:a[`CUSTOM_${n.toUpperCase()}_TOKEN`]}),f=o.Z.get({id:"SKIN_CUSTOMIZATIONS",url:r,params:{action:"edit_customization"},schema:{name:o.Z.REQUIRED_STRING},mapResponse:{colors:n=>n.HAS_CUSTOMIZATION==="1"&&!!n.SKIN_CUSTOM_COLOR_1,uploads:{logo:c("logo"),logo2:c("logo2"),favicon:c("favicon"),symbol:c("symbol"),symbol2:c("symbol2")}}})},"./js/pages/reseller/skins.vue":function(S,d,l){l.r(d),l.d(d,{default:function(){return y}});var o=function(){var e=this,t=e._self._c;return t("app-page",{attrs:{actions:[{handler:e.$dialog("UPLOAD_SKIN_DIALOG").open,label:e.$gettext("Upload Skin"),icon:"#upload",theme:"safe"}]},scopedSlots:e._u([{key:"default",fn:function(){return[t("app-page-section",[t("ui-r-table",{attrs:{rows:e.$api.skins,columns:[{id:"skin",label:e.$gettext("Skin Name"),grow:!0,editable:!1},{id:"path",label:e.$gettext("Path")},{id:"owner",label:e.$gettext("Skin Owner")}],"vertical-layout":e.clientStore.isPhone,"checked-rows":e.checkedRows,"disable-pagination":""},on:{"update:checkedRows":function(s){e.checkedRows=s}},scopedSlots:e._u([{key:"table:actions",fn:function(){return[e.checkedSkins.length===1?t("ui-table-action",{on:{click:function(s){return e.applySkin("reseller")}}},[t("span",{domProps:{textContent:e._s(e.$gettext("Apply to Me"))}})]):e._e(),e._v(" "),e.checkedSkins.length===1?t("ui-table-action",{on:{click:function(s){return e.applySkin("all")}}},[t("span",{domProps:{textContent:e._s(e.$gettext("Apply to All Users"))}})]):e._e(),e._v(" "),e.$_useStore("user").hasRole("admin")?t("ui-table-action",{attrs:{disabled:e.checkedSkins.length!==1},on:{click:e.setGlobal}},[t("span",{domProps:{textContent:e._s(e.$gettext("Set Global"))}})]):e._e(),e._v(" "),t("ui-table-action",{on:{click:function(s){e.$dialog("DELETE_SKINS_DIALOG").open()}}},[t("span",{domProps:{textContent:e._s(e.$gettext("Delete"))}})])]},proxy:!0},{key:"col:skin",fn:function({skin:s}){return[t("ui-grid",[t("span",{domProps:{textContent:e._s(s)}}),e._v(" "),s===e.currentSkin?t("ui-badge",{attrs:{theme:"primary",size:"small"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Current"))}})]):e._e()],1)]}}])})],1),e._v(" "),t("upload-skin-dialog",{on:{uploaded:e.reloadSkins}}),e._v(" "),t("ui-dialog-delete-items",{attrs:{id:"DELETE_SKINS_DIALOG",subject:e.$ngettext("selected skin","selected skins",e.checkedSkins.length)},on:{"click:confirm":e.deleteSkins}})]},proxy:!0}])})},r=[],p=l("./js/stores/index.ts"),i=l("./js/api/commands/reseller/skins.js"),_=function(){var e=this,t=e._self._c;return t("ui-dialog",e._g({attrs:{id:"UPLOAD_SKIN_DIALOG","no-auto-close":"",title:e.$gettext("Upload Skin")},on:{"dialog:close":e.resetData},scopedSlots:e._u([{key:"content",fn:function(){return[t("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"content",fn:function(){return[t("input-dropzone",{attrs:{accept:[".tar.gz"]},model:{value:e.file,callback:function(s){e.file=s},expression:"file"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{group:"uploadSkin",validators:{required:!0},vertical:""},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Name"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{scopedSlots:e._u([{key:"additions:right",fn:function(){return[t("input-checkbox-button",{model:{value:e.serverwide,callback:function(s){e.serverwide=s},expression:"serverwide"}},[t("span",{staticClass:"wrap:nowrap",domProps:{textContent:e._s(e.$gettext("Server wide"))}})])]},proxy:!0}]),model:{value:e.name,callback:function(s){e.name=s},expression:"name"}})]},proxy:!0}])})]},proxy:!0},{key:"buttons",fn:function(){return[t("ui-button",{attrs:{theme:"safe","validate-group":"uploadSkin",disabled:!e.file},on:{click:e.uploadSkin}},[t("span",{domProps:{textContent:e._s(e.$gettext("Upload"))}})])]},proxy:!0}])},e.$listeners))},k=[],m={data:()=>({name:"",serverwide:!0,file:null}),methods:{async uploadSkin(){await(0,i.UF)({file:this.file,name:this.name,server:this.serverwide})&&(this.$emit("uploaded"),this.$dialog("UPLOAD_SKIN_DIALOG").close())},resetData(){Object.assign(this.$data,this.$options.data.apply(this))}}},c=m,f=l("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),n=(0,f.Z)(c,_,k,!1,null,null,null),a=n.exports,h={name:"ResellerSkins",preload:i.$Y,api:[{command:i.$Y,bind:"skins"}],components:{UploadSkinDialog:a},data:()=>({checkedRows:[],selectedSkin:null}),computed:{currentSkin(){return this.$_session.skin},checkedSkins(){return this.checkedRows.map(u=>u.skin)},...(0,p.Kc)(["client"])},methods:{reloadSkins(){(0,i.$Y)(),this.checkedRows=[]},async deleteSkins(){(0,i.eD)({select:this.checkedSkins}).then(this.reloadSkins)},async applySkin(u){await(0,i.br)({select:this.checkedSkins,apply_as:u}),this.checkSkin(),this.$_ctx.session.loadUserConfig()},checkSkin(){this.checkedSkins[0]!=="evolution"&&(window.location="/")},async setGlobal(){await(0,i.v0)({select:this.checkedSkins}),this.checkSkin(),this.$_ctx.session.loadUserConfig()}}},g=h,v=(0,f.Z)(g,o,r,!1,null,null,null),y=v.exports}}]);