(self.webpackChunk=self.webpackChunk||[]).push([[788],{"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/reseller/cpanel/start.vue?vue&type=style&index=0&id=f46f1a76&prod&lang=scss&":function(){},"./js/openapi/cpanel.ts":function(m,c,n){"use strict";n.d(c,{Ak:function(){return p},C2:function(){return v},Di:function(){return d},_5:function(){return _},yS:function(){return x}});var o=n("./js/api/openapi/index.ts"),i=n("../node_modules/runtypes/lib/index.js"),f=n.n(i),l=n("./js/openapi/web.types.ts");const a=(0,o.$d)(),d=o.an.Default(async(u,s)=>{const{data:e}=await a.post("/api/cpanel-import/check-remote",u,s);return e.status==="success"&&l.Tf.guard(e.data)===!1?a.failure({type:"INVALID_RESPONSE",response:e.data}):e}),p=o.an.Default(async u=>{const{data:s}=await a.get("/api/cpanel-import/tasks",u);return s.status==="success"&&i.Array(l.hr).guard(s.data)===!1?a.failure({type:"INVALID_RESPONSE",response:s.data}):s}),v=o.an.Default(async(u,s)=>{const{data:e}=await a.post("/api/cpanel-import/tasks/start",u,s);return e.status==="success"&&i.Array(l.hr).guard(e.data)===!1?a.failure({type:"INVALID_RESPONSE",response:e.data}):e}),g=o.an.Default(async(u,s)=>{const{data:e}=await a.get(`/api/cpanel-import/tasks/${u}`,s);return e.status==="success"&&l.hr.guard(e.data)===!1?a.failure({type:"INVALID_RESPONSE",response:e.data}):e}),_=o.an.Default(async(u,s)=>{const{data:e}=await a.delete(`/api/cpanel-import/tasks/${u}`,s);return e}),y=async(u,s)=>{const{data:e}=await a.get(`/api/cpanel-import/tasks/${u}/log`,s);return e.status==="success"&&rt.Array(web.rtCpanelImportTaskLog).guard(e.data)===!1?a.failure({type:"INVALID_RESPONSE",response:e.data}):e};class x extends o.MF{constructor(){super(...arguments),this.streamType=o.MF.JSON_STREAM,this.validator=l.J0}open(s,e){return super.connect(`/api/cpanel-import/tasks/${s}/log-sse`,e||{})}}},"./js/pages/reseller/cpanel/start.vue":function(m,c,n){"use strict";n.r(c),n.d(c,{default:function(){return u},notifyError:function(){return p}});var o=function(){var e=this,t=e._self._c;return t("app-page",{scopedSlots:e._u([{key:"default",fn:function(){return[t("app-page-section",{scopedSlots:e._u([{key:"section:title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Remote cPanel server credentials"))}})]},proxy:!0},{key:"default",fn:function(){return[t("ui-form-element",{attrs:{group:"import",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Host"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.host,callback:function(r){e.host=r},expression:"host"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{group:"import",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Port"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{staticClass:"port-input",attrs:{number:""},model:{value:e.port,callback:function(r){e.port=r},expression:"port"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{group:"import",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("User"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.user,callback:function(r){e.user=r},expression:"user"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{underline:!1,group:"import",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Password"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-password",{model:{value:e.pass,callback:function(r){e.pass=r},expression:"pass"}})]},proxy:!0}])})]},proxy:!0},{key:"footer:buttons",fn:function(){return[t("ui-button",{attrs:{theme:"primary","validate-group":"import"},on:{click:e.checkRemote}},[t("span",{domProps:{textContent:e._s(e.$gettext("Load Accounts"))}})])]},proxy:!0}])}),e._v(" "),e.remoteMode==="passed"?t("app-page-section",{scopedSlots:e._u([{key:"section:title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Accounts to import"))}})]},proxy:!0},{key:"default",fn:function(){return[t("ui-r-table",{attrs:{rows:e.filteredAccountsList,"checked-rows":e.accounts,columns:[{id:"user",label:e.$gettext("Account")},{id:"email",label:e.$gettext("Email")},{id:"domain",label:e.$gettext("Domain")},{id:"plan",label:e.$gettext("Plan")},{id:"ip",label:e.$gettext("IP")},{id:"owner",label:e.$gettext("Owner")}]},on:{"update:checkedRows":function(r){e.accounts=r}},scopedSlots:e._u([{key:"buttons:before",fn:function(){return[t("input-text",{attrs:{placeholder:e.$gettext("Filter Accounts")},model:{value:e.searchValue,callback:function(r){e.searchValue=r},expression:"searchValue"}})]},proxy:!0},{key:"col:user",fn:function({item:r}){return[t("div",{directives:[{name:"flex",rawName:"v-flex",value:{dir:"row",cross:"center"},expression:"{ dir: 'row', cross: 'center' }"}],staticClass:"wrap:nowrap"},[e._v(`
                            `+e._s(r.user)+`
                            `),r.reseller||r.suspended?t("div",{directives:[{name:"margin",rawName:"v-margin:left",value:.5,expression:"0.5",arg:"left"}]},[r.reseller?t("ui-badge",{attrs:{theme:"primary",size:"small"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Reseller"))}})]):e._e(),e._v(" "),r.suspended?t("ui-badge",{directives:[{name:"margin",rawName:"v-margin:left",value:1,expression:"1",arg:"left"}],attrs:{theme:"danger",size:"small"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Suspended"))}})]):e._e()],1):e._e()])]}}],null,!1,3367788763)}),e._v(" "),e.homeOverrides.length?t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Override home directory"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-select",{attrs:{options:e.homeOverrides},model:{value:e.homeOverride,callback:function(r){e.homeOverride=r},expression:"homeOverride"}})]},proxy:!0}],null,!1,1984853949)}):e._e(),e._v(" "),t("ui-form-element",{attrs:{group:"import",validators:{required:!0,gte:1,lte:20},underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Workers"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{attrs:{number:""},model:{value:e.maxWorkers,callback:function(r){e.maxWorkers=r},expression:"maxWorkers"}})]},proxy:!0},{key:"error:gte",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Max workers must be greater than 0"))}})]},proxy:!0},{key:"error:lte",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Max workers must be less than 20"))}})]},proxy:!0}],null,!1,1484608608)}),e._v(" "),t("ui-form-element",{attrs:{underline:!1,vertical:""},scopedSlots:e._u([{key:"content",fn:function(){return[t("div",{directives:[{name:"margin",rawName:"v-margin:left",value:1,expression:"1",arg:"left"},{name:"flex",rawName:"v-flex",value:{cross:"center"},expression:"{ cross: 'center' }"}]},[t("input-checkbox",{model:{value:e.replaceExistingUser,callback:function(r){e.replaceExistingUser=r},expression:"replaceExistingUser"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Replace existing user"))}})]),e._v(" "),t("input-checkbox",{directives:[{name:"margin",rawName:"v-margin:left",value:1.5,expression:"1.5",arg:"left"}],model:{value:e.ignoreConvertErrors,callback:function(r){e.ignoreConvertErrors=r},expression:"ignoreConvertErrors"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Ignore convert errors"))}})]),e._v(" "),t("input-checkbox",{directives:[{name:"margin",rawName:"v-margin:left",value:1.5,expression:"1.5",arg:"left"}],model:{value:e.preserveOwner,callback:function(r){e.preserveOwner=r},expression:"preserveOwner"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Preserve owner"))}})])],1)]},proxy:!0}],null,!1,3176062012)})]},proxy:!0},{key:"footer:buttons",fn:function(){return[t("ui-button",{attrs:{theme:"primary",disabled:e.accounts.length===0,"validate-group":"import"},on:{click:e.startImport}},[t("span",{domProps:{textContent:e._s(e.$gettext("Run import"))}})])]},proxy:!0}],null,!1,2975020764)}):e._e()]},proxy:!0}])})},i=[],f=n("./js/openapi/cpanel.ts"),l=n("../node_modules/ramda/es/index.js"),a=n("./js/composables/index.ts");const{$gettext:d}=(0,a.st)(),p=(0,a.Lu)({CPANEL_IMPORT_SSH_CONNECTION_FAILED:d("Could not connect to remote host"),CPANEL_IMPORT_SSH_AUTH_FAILED:d("Username or password is incorrect"),CPANEL_IMPORT_SSH_NOT_CPANEL_SERVER:d("SSH server is not cPanel server")});var v={name:"CpanelImportList",data:()=>({host:"",pass:"",port:22,user:"root",preserveOwner:!1,homeOverride:"",maxWorkers:"1",remoteMode:"not-checked",accounts:[],accountsList:[],ignoreConvertErrors:!1,replaceExistingUser:!0,searchValue:""}),computed:{filteredAccountsList(){const s=l.q9t(this.searchValue),e=l.jCC(s),t=l.H50([e("user"),e("domain"),e("ip"),e("email"),e("owner")]);return l.hXT(t,this.accountsList)},homeOverrides(){return this.$_session.homeOverrides},importRequestPayload(){const s=this.accounts.map(t=>t.user),e={remoteHost:this.host,remotePort:Number(this.port)||22,remoteUser:this.user,remotePassword:this.pass,accounts:s,ignoreConvertErrors:this.ignoreConvertErrors,replaceExistingUser:this.replaceExistingUser,preserveOwner:this.preserveOwner,maxWorkers:Number(this.maxWorkers)};return this.homeOverride!==""&&(e.homeOverride=this.homeOverride),e}},watch:{host:"resetCheck",port:"resetCheck",user:"resetCheck",pass:"resetCheck"},methods:{resetCheck(){this.remoteMode="not-checked"},async checkRemote(){this.remoteMode="not-checked",this.accounts=[],this.accountsList=[];const{data:s,error:e}=await(0,f.Di)({remoteHost:this.host,remotePort:Number(this.port)||22,remoteUser:this.user,remotePassword:this.pass});if(e){p(e),this.remoteMode="error";return}if(!s||s.accounts.length===0){(0,a.d$)().error({title:d("Error"),content:d("There is no accounts that can be imported")});return}this.remoteMode="passed",this.accountsList=s.accounts},async startImport(){const{error:s}=await(0,f.C2)(this.importRequestPayload);if(s){p(s);return}this.$router.push({name:"reseller/cpanel-import"})}}},g=v,_=n("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/reseller/cpanel/start.vue?vue&type=style&index=0&id=f46f1a76&prod&lang=scss&"),y=n("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),x=(0,y.Z)(g,o,i,!1,null,null,null),u=x.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/reseller/cpanel/start.vue?vue&type=style&index=0&id=f46f1a76&prod&lang=scss&":function(m,c,n){var o=n("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/reseller/cpanel/start.vue?vue&type=style&index=0&id=f46f1a76&prod&lang=scss&");o.__esModule&&(o=o.default),typeof o=="string"&&(o=[[m.id,o,""]]),o.locals&&(m.exports=o.locals);var i=n("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,f=i("66fd185d",o,!0,{})}}]);
