"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[8615],{"./js/pages/admin/plugin-manager.vue":function(_,u,l){l.r(u),l.d(u,{default:function(){return v}});var d=function(){var t=this,e=t._self._c;return e("app-page",{attrs:{actions:[{handler:t.$dialog("ADD_PLUGIN_DIALOG").open,label:t.$gettext("Add Plugin"),icon:"#plus-fill"}]},scopedSlots:t._u([{key:"default",fn:function(){return[e("app-page-section",[e("ui-r-table",{attrs:{"is-checkable":!1,rows:t.plugins,columns:[{id:"name",label:t.$gettext("Plugin"),grow:!0,editable:!1},{id:"version",label:t.$gettext("Version")},{id:"available_version",label:t.$gettext("Available Version")},{id:"active",label:t.$gettext("Active")},{id:"can_update",label:t.$gettext("Can Update")},{id:"installed",label:t.$gettext("Installed")},{id:"author",label:t.$gettext("Author"),grow:!0}],"vertical-layout":t.clientStore.isPhone,"disable-pagination":""},scopedSlots:t._u([{key:"col:name",fn:function({name:n,id:i}){return[e("ui-grid",{attrs:{cross:"center"}},[e("span",{domProps:{textContent:t._s(n||i)}}),t._v(" "),n?t._e():e("ui-tooltip",{attrs:{theme:"danger"}},[e("span",{domProps:{textContent:t._s(t.$gettext("Corrupted Plugin"))}})])],1)]}},{key:"col:active",fn:function({active:n}){return[e("ui-badge",{attrs:{theme:n?"safe":"danger",size:"small"}},[e("span",{domProps:{textContent:t._s(n?t.$gettext("Yes"):t.$gettext("No"))}})])]}},{key:"col:can_update",fn:function({available_version:n}){return[e("ui-badge",{attrs:{theme:n?"safe":"danger",size:"small"}},[e("span",{domProps:{textContent:t._s(n?t.$gettext("Yes"):t.$gettext("No"))}})])]}},{key:"col:installed",fn:function({installed:n}){return[e("ui-badge",{attrs:{theme:n?"safe":"danger",size:"small"}},[e("span",{domProps:{textContent:t._s(n?t.$gettext("Yes"):t.$gettext("No"))}})])]}},{key:"row:actions",fn:function({name:n,id:i,active:P,available_version:y,installed:r}){return[e("ui-actions",{attrs:{position:"left"}},[r?[P?e("ui-link",{key:"deactivate-link",on:{click:function(s){return t.pluginAction("deactivate",i)}}},[e("span",{domProps:{textContent:t._s(t.$gettext("Deactivate"))}})]):e("ui-link",{key:"activate-link",on:{click:function(s){return t.pluginAction("activate",i)}}},[e("span",{domProps:{textContent:t._s(t.$gettext("Activate"))}})])]:t._e(),t._v(" "),y?e("ui-link",{key:"update-link",on:{click:function(s){return t.pluginAction("update",i)}}},[e("span",{domProps:{textContent:t._s(t.$gettext("Update"))}})]):t._e(),t._v(" "),!r&&n?e("ui-link",{key:"install-link",on:{click:function(s){return t.pluginAction("install",i)}}},[e("span",{domProps:{textContent:t._s(t.$gettext("Install"))}})]):e("ui-link",{key:"uninstall-link",on:{click:function(s){return t.pluginAction("uninstall",i)}}},[e("span",{domProps:{textContent:t._s(t.$gettext("Un-Install"))}})]),t._v(" "),e("ui-link",{key:"delete-link",on:{click:function(s){return t.pluginAction("delete",i)}}},[e("span",{domProps:{textContent:t._s(t.$gettext("Delete"))}})])],2)]}}])})],1),t._v(" "),e("ui-dialog",{attrs:{id:"ADD_PLUGIN_DIALOG",title:t.$gettext("Add Plugin")},scopedSlots:t._u([{key:"content",fn:function(){return[e("div",[e("ui-form-element",{scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("Upload Method:"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-radio",{attrs:{value:"url"},model:{value:t.addPluginData.method,callback:function(n){t.$set(t.addPluginData,"method",n)},expression:"addPluginData.method"}},[e("span",{domProps:{textContent:t._s(t.$gettext("URL"))}})]),t._v(" "),e("input-radio",{attrs:{value:"file"},model:{value:t.addPluginData.method,callback:function(n){t.$set(t.addPluginData,"method",n)},expression:"addPluginData.method"}},[e("span",{domProps:{textContent:t._s(t.$gettext("File"))}})])]},proxy:!0}])}),t._v(" "),e("transition",{attrs:{name:"fade",mode:"out-in"}},[t.addPluginData.method==="url"?e("ui-form-element",{key:"url",attrs:{vertical:""},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("URL"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input",{directives:[{name:"model",rawName:"v-model",value:t.addPluginData.url,expression:"addPluginData.url"}],attrs:{type:"text"},domProps:{value:t.addPluginData.url},on:{input:function(n){n.target.composing||t.$set(t.addPluginData,"url",n.target.value)}}})]},proxy:!0}],null,!1,2010042586)}):e("ui-form-element",{key:"file",attrs:{vertical:""},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("File"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-dropzone",{attrs:{accept:["application/gzip","application/tgz"]},model:{value:t.addPluginData.file,callback:function(n){t.$set(t.addPluginData,"file",n)},expression:"addPluginData.file"}})]},proxy:!0}])})],1),t._v(" "),e("ui-form-element",{attrs:{vertical:""},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("Password"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-password",{model:{value:t.addPluginData.passwd,callback:function(n){t.$set(t.addPluginData,"passwd",n)},expression:"addPluginData.passwd"}})]},proxy:!0}])}),t._v(" "),e("ui-form-element",{scopedSlots:t._u([{key:"content",fn:function(){return[e("input-checkbox",{model:{value:t.addPluginData.install,callback:function(n){t.$set(t.addPluginData,"install",n)},expression:"addPluginData.install"}},[e("span",{domProps:{textContent:t._s(t.$gettext("Install after upload"))}})])]},proxy:!0}])})],1)]},proxy:!0},{key:"buttons",fn:function(){return[e("ui-button",{attrs:{theme:"primary"},on:{click:t.addPlugin}},[e("span",{domProps:{textContent:t._s(t.addPluginData.method==="url"?t.$gettext("Install"):t.$gettext("Upload"))}})])]},proxy:!0}])}),t._v(" "),e("ui-dialog-confirm",{attrs:{id:"CONFIRMATION_DIALOG"},on:{"click:confirm":t.doAction,"dialog:close":function(n){t.addPluginData.passwd=""}}},[t.currentActionData.action==="deactivate"?e("span",[t._v(`
                `+t._s(t.$gettextInterpolate(t.$gettext('Are you sure you want to deactivate "%{ name }" plugin?'),{name:t.getPluginName(t.currentActionData.id)}))+`
            `)]):t.currentActionData.action==="activate"?e("span",[t._v(`
                `+t._s(t.$gettextInterpolate(t.$gettext('Are you sure you want to activate "%{ name }" plugin?'),{name:t.getPluginName(t.currentActionData.id)}))+`
            `)]):t.currentActionData.action==="update"?e("span",[t._v(`
                `+t._s(t.$gettextInterpolate(t.$gettext('Are you sure you want to update "%{ name }" plugin?'),{name:t.getPluginName(t.currentActionData.id)}))+`
            `)]):t.currentActionData.action==="install"?e("span",[t._v(`
                `+t._s(t.$gettextInterpolate(t.$gettext('Are you sure you want to install "%{ name }" plugin?'),{name:t.getPluginName(t.currentActionData.id)}))+`
            `)]):t.currentActionData.action==="uninstall"?e("span",[t._v(`
                `+t._s(t.$gettextInterpolate(t.$gettext('Are you sure you want to uninstall "%{ name }" plugin?'),{name:t.getPluginName(t.currentActionData.id)}))+`
            `)]):e("span",[t._v(`
                `+t._s(t.$gettextInterpolate(t.$gettext('Are you sure you want to delete "%{ name }" plugin?'),{name:t.getPluginName(t.currentActionData.id)}))+`
            `)]),t._v(" "),e("ui-form-element",{attrs:{vertical:""},scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("Password"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-password",{model:{value:t.addPluginData.passwd,callback:function(n){t.$set(t.addPluginData,"passwd",n)},expression:"addPluginData.passwd"}})]},proxy:!0}])})],1)]},proxy:!0}])})},c=[],p=l("./js/stores/index.ts"),o=l("./js/api/commands/plugins.js"),g={preload:o.eX,api:[{command:o.eX,bind:"plugins"}],data(){return{addPluginData:{method:"url",url:"",file:null,passwd:"",install:!0},currentActionData:{action:"",id:""}}},computed:{plugins(){return this.$api.plugins},...(0,p.Kc)(["client"])},methods:{getPluginName(a){const t=this.plugins.find(e=>e.id===a);return t?t.name:""},async addPlugin(){const a={url:o.Tk,file:o.GH}[this.addPluginData.method];try{await a(this.addPluginData),this.reloadPlugins()}catch(t){}finally{(0,o.eX)()}},async pluginAction(a,t){this.currentActionData={action:a,id:t},this.$dialog("CONFIRMATION_DIALOG").open()},async reloadPlugins(){const a=this.$_useStore("navigation"),t=this.$_useStore("user");a.resetPlugins(),a.loadPlugins(t.mode)},async doAction(){const{action:a,id:t}=this.currentActionData;await(0,o.ky)({[a]:!0,select:[t],passwd:this.addPluginData.passwd})&&(this.reloadPlugins(),this.currentActionData={id:"",action:""},(0,o.eX)())}}},m=g,f=l("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),x=(0,f.Z)(m,d,c,!1,null,null,null),v=x.exports}}]);