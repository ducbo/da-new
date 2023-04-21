(self.webpackChunk=self.webpackChunk||[]).push([[6221],{"./js/api/commands/admin/httpd.js":function(_,f,o){"use strict";o.d(f,{J_:function(){return g},Nk:function(){return h},Pw:function(){return l},Yy:function(){return y},ad:function(){return i},ay:function(){return t},du:function(){return j},hF:function(){return u},tl:function(){return p}});var s=o("./js/api/command/index.js"),e=o("./js/modules/utils/index.js");const c=e.fp.flow(e.fp.convert.toAppString,e.fp.convert.toLines),a=e.fp.flow(n=>n||"",e.fp.convert.toAppString,e.fp.convert.toAppText),m="/CMD_CUSTOM_HTTPD",h=s.Z.get({id:"CUSTOM_HTTPD_DOMAINS",url:m,pagination:!0,after:()=>e.fp.flow(e.fp.mapProp("domains",e.fp.toTable()),e.fp.mapProp("file",e.fp.feedWith(1,n=>["nginx","nginx_proxy","openlitespeed","httpd"].find(r=>n[`have_${r}`]==="1")||"httpd")))}),j=s.Z.post({url:m,params:{action:"all",rewrite_confs:!0}}),y=s.Z.get({url:m,id:"CH_DOMAIN_CONFIG",schema:{domain:s.Z.REQUIRED_STRING,proxy:s.Z.OPTIONAL_BOOL},after:()=>e.fp.flow(n=>({tokens:n.AVAILABLE_TOKENS,error:n.CONFIG_ERROR,test:n.CONFIG_TEST,data:n.HTTPD,templates:n}),e.fp.mapProps({error:e.fp.isEqual("1"),nginx:e.fp.isEqual("1"),data:c,test:a,templates:e.fp.flow(e.fp.filter((n,r)=>r.includes("VH")),e.fp.filter(e.fp.getProp("data")),e.fp.toArray,e.fp.mapArrayProps({data:c,custom:e.fp.isEqual("1")})),tokens:e.fp.flow(e.fp.mapValues((n,r)=>({token:r,value:n})),e.fp.toArray)}))}),g=s.Z.get({url:m,id:"CH_DOMAIN_CUSTOMIZATION_VALUES",schema:{domain:s.Z.REQUIRED_STRING,proxy:s.Z.OPTIONAL_BOOL},after:()=>e.fp.flow(e.fp.project({config:"CONFIG",custom1:"CUSTOM1",custom2:"CUSTOM2",custom3:"CUSTOM3",custom4:"CUSTOM4",custom5:"CUSTOM5",custom6:"CUSTOM6",custom7:"CUSTOM7",custom8:"CUSTOM8",tokens:"AVAILABLE_TOKENS",appendix:"VH1.custom_global_pre_post",tokensCount:"NUM_CUSTOM_TOKENS"}),e.fp.mapProps({config:a,custom1:a,custom2:a,custom3:a,custom4:a,custom5:a,custom6:a,custom7:a,custom8:a,nginx:e.fp.convert.toAppBoolean,tokensCount:e.fp.convert.toAppNumber,tokens:e.fp.flow(e.fp.mapValues((n,r)=>({token:r,value:n})),e.fp.toArray),appendix:e.fp.flow(e.fp.setDefault({}),e.fp.filter((n,r)=>r.includes("CUSTOM")),e.fp.mapValues(a),e.fp.transformObject((n,r)=>{const[,T]=r.match(/^.*(CUSTOM.*)$/);return{[T]:{data:n,name:r}}}))}))}),l=s.Z.post({url:m,schema:{proxy:s.Z.OPTIONAL_STRING,domain:s.Z.REQUIRED_STRING,config:s.Z.OPTIONAL_STRING,custom1:s.Z.OPTIONAL_STRING,custom2:s.Z.OPTIONAL_STRING,custom3:s.Z.OPTIONAL_STRING,custom4:s.Z.OPTIONAL_STRING,custom5:s.Z.OPTIONAL_STRING,custom6:s.Z.OPTIONAL_STRING,custom7:s.Z.OPTIONAL_STRING,custom8:s.Z.OPTIONAL_STRING}}),p=s.Z.get({url:m,id:"CH_PHP_FPM_CONFIGURATION",schema:{user:s.Z.REQUIRED_STRING,"php-fpm":s.Z.REQUIRED_STRING},after:()=>e.fp.flow(e.fp.project({error:"CONFIG_ERROR",test:"CONFIG_TEST",custom1:"CUSTOM1",custom2:"CUSTOM2",global_custom1:"GLOBAL_CUSTOM1",global_custom2:"GLOBAL_CUSTOM2","config.data":"FPM_CONFIG","config.file":"FPM_CONFIG_FILE","config.version":"FPM_VER","template.custom":"PHP_FPM_IS_CUSTOM_TEMPLATE","template.data":"PHP_FPM_TEMPLATE","template.name":"PHP_FPM_TEMPLATE_NAME","template.short":"PHP_FPM_TEMPLATE_NAME_SHORT"}),e.fp.mapProps({error:e.fp.isEqual("1"),test:a,custom1:a,custom2:a,config:e.fp.mapProp("data",c),template:e.fp.mapProps({custom:e.fp.isEqual("1"),data:c})}))}),u=s.Z.get({id:"CH_PHP_FPM_TOKENS",url:m,schema:{user:s.Z.REQUIRED_STRING,"php-fpm":s.Z.REQUIRED_STRING},after:()=>e.fp.flow(e.fp.getProp("AVAILABLE_TOKENS"),e.fp.mapValues((n,r)=>({token:r,value:n})),e.fp.toArray)}),t=s.Z.post({url:m,schema:{user:s.Z.REQUIRED_STRING,"php-fpm":s.Z.REQUIRED_STRING,custom1:s.Z.OPTIONAL_STRING,custom2:s.Z.OPTIONAL_STRING,all_php_versions:s.Z.OPTIONAL_BOOL}}),i=s.Z.get({id:"CH_DIFF",url:"/CMD_TEMPLATE_DIFF",schema:{name:s.Z.REQUIRED_STRING},after:()=>e.fp.flow(e.fp.deleteProp("lines"),e.fp.mapValues((n,r)=>({...n,number:r})),e.fp.toArray,e.fp.mapArray(e.fp.moveProp("line","content")),e.fp.mapArrayProps({number:e.fp.convert.toAppNumber,content:n=>n?n.replace(/\t/g,"    "):""}),e.fp.sortBy("number"))})},"./js/vue-globals/mixins/local/inputValidation.js":function(_,f,o){"use strict";o.r(f),o.d(f,{$inputValidation:function(){return c}});var s=o("./js/vue-globals/helpers.js"),e=o("./js/stores/index.ts");const c={inject:{groupID:{default:null},inputID:{default:null},validators:{default:()=>({})}},props:{id:{type:String,required:!1,default(){return this.inputID}},group:{type:String,required:!1,default(){return this.groupID}},novalidate:{type:Boolean,required:!1,default(){return!Object.keys(this.validators).length}}},computed:{validationStore(){return(0,e.oR)(PiniaStores.VALIDATION)},valid(){return this.validationStore.isValid(this.group,this.id)},errorState(){return!this.novalidate&&this.isUpdated&&!this.valid},isUpdated(){var a;const m=(a=this.validationStore.groups[this.group])==null?void 0:a[this.id];return typeof m=="undefined"?!1:m.updated}},methods:{$validate(a){this.id&&!this.novalidate&&this.validationStore.validate(this.groupID,this.id,a,this.validators)}},created(){if(!this.novalidate){const{validate:a}=this.$options;a&&this.$watch(a,(0,s.Ds)(this.$validate,{trailing:!0,leading:!1,delay:200}),{immediate:!0})}},destroyed(){this.novalidate||this.validationStore.deleteInput(this.group,this.id)}}},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&":function(){},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custom-httpd/view.vue?vue&type=style&index=0&id=5c1a7204&prod&lang=scss&scoped=true&":function(){},"./js/components/local/inputs/input-text-editor.vue":function(_,f,o){"use strict";o.d(f,{Z:function(){return E}});var s=function(){var d=this,v=d._self._c;return v("div",{staticClass:"input-text-editor"},[d.$slots.header||d.$scopedSlots.header?v("div",{staticClass:"input-text-editor-header"},[d._t("header")],2):d._e(),d._v(" "),v("codemirror",{ref:"editor",attrs:{value:d.value,options:{lineNumbers:!0,readOnly:d.readOnly,mode:d.cmMode,theme:d.theme}},on:{input:function(S){return d.$emit("input",S)}}}),d._v(" "),!d.disableModes||!d.disableThemes?v("div",{staticClass:"input-text-editor-bottom-bar"},[d._t("bottom"),d._v(" "),v("span",{directives:[{name:"flex-item",rawName:"v-flex-item",value:{grow:!0},expression:"{ grow: true }"}]}),d._v(" "),d.disableModes?d._e():v("input-select",{staticClass:"input-text-editor-bottom-bar-select",attrs:{options:d.modes},scopedSlots:d._u([{key:"additions:left",fn:function(){return[v("ui-button",{attrs:{disabled:""}},[v("span",{domProps:{textContent:d._s(d.$gettext("Mode:"))}})])]},proxy:!0}],null,!1,42350692),model:{value:d.editorMode,callback:function(S){d.editorMode=S},expression:"editorMode"}}),d._v(" "),d.disableThemes?d._e():v("input-select",{staticClass:"input-text-editor-bottom-bar-select --wide",attrs:{options:d.themes},scopedSlots:d._u([{key:"additions:left",fn:function(){return[v("ui-button",{attrs:{disabled:""}},[v("span",{domProps:{textContent:d._s(d.$gettext("Theme:"))}})])]},proxy:!0}],null,!1,3964340662),model:{value:d.theme,callback:function(S){d.theme=S},expression:"theme"}})],2):d._e()],1)},e=[],c=o("../node_modules/vue-codemirror/dist/vue-codemirror.js"),a=o("../node_modules/codemirror/mode/javascript/javascript.js"),m=o("../node_modules/codemirror/mode/htmlmixed/htmlmixed.js"),h=o("../node_modules/codemirror/mode/css/css.js"),j=o("../node_modules/codemirror/mode/php/php.js"),y=o("../node_modules/codemirror/mode/perl/perl.js"),g=o("../node_modules/codemirror/mode/properties/properties.js"),l=o("../node_modules/codemirror/mode/xml/xml.js"),p=o("../node_modules/codemirror/mode/sql/sql.js"),u=o("./js/modules/utils/index.js"),t=o("../node_modules/vue/dist/vue.common.prod.js"),i=o("./js/vue-globals/mixins/local/inputValidation.js"),n=o("./js/context/index.ts"),r=o("./js/modules/dark-mode.ts");const T=["default","base16-light","base16-dark","monokai","solarized"],O=["text","html","javascript","css","php","perl","ini","xml","sql","mysql","json"],P=x=>d=>x.includes(d);c.codemirror.beforeDestroy=void 0;var R={components:{codemirror:c.codemirror},mixins:[i.$inputValidation],validate:"value",props:{value:{type:String,required:!0,default:""},readOnly:{type:Boolean,required:!1,default:!1},mode:{type:String,required:!1,default:"text",validator:P(O)},disableModes:{type:Boolean,required:!1,default:!1},disableThemes:{type:Boolean,required:!1,default:!1}},data(){return{editorMode:this.mode,theme:"default"}},staticData:{modes:O,themes:T},computed:{cmMode(){switch(this.editorMode){case"json":return{name:"javascript",json:!0};case"mysql":return"sql";case"ini":return"properties";default:return this.editorMode}}},mounted(){(0,t.watch)(()=>n.T.options["code-editor/theme"],x=>{this.theme=x},{immediate:!0}),(0,r.Uu)(x=>{this.theme=x==="dark"?"base16-dark":n.T.options["code-editor/theme"]})}},I=R,N=o("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&"),b=o("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),C=(0,b.Z)(I,s,e,!1,null,null,null),E=C.exports},"./js/pages/admin/custom-httpd/_dialogs/available-tokens-dialog.vue":function(_,f,o){"use strict";o.d(f,{Z:function(){return y}});var s=function(){var l=this,p=l._self._c;return p("ui-dialog",{attrs:{id:"VIEW_ALL_AVAILABLE_TOKENS",size:"normal",title:l.$gettext("View All Available Tokens")},scopedSlots:l._u([{key:"content",fn:function(){return[p("div",[p("ui-form-element",{attrs:{underline:!1},scopedSlots:l._u([{key:"title",fn:function(){return[p("span",{domProps:{textContent:l._s(l.$gettext("Filter Tokens"))}})]},proxy:!0},{key:"content",fn:function(){return[p("ui-input-group",{scopedSlots:l._u([{key:"input",fn:function(){return[p("input-text",{model:{value:l.search,callback:function(u){l.search=u},expression:"search"}})]},proxy:!0},{key:"additions:right",fn:function(){return[p("ui-button",{attrs:{theme:"light"},on:{click:function(u){l.hideEmpty=!l.hideEmpty}}},[p("input-checkbox",{model:{value:l.hideEmpty,callback:function(u){l.hideEmpty=u},expression:"hideEmpty"}},[p("span",{domProps:{textContent:l._s(l.$gettext("Hide Empty"))}})])],1)]},proxy:!0}])})]},proxy:!0}])}),l._v(" "),p("ui-r-table",l._b({attrs:{"vertical-layout":l.clientStore.isPhone,"disable-pagination":"","hide-before-controls":"","unstick-headers":""}},"ui-r-table",{rows:l.filtered,columns:[{id:"token",label:l.$gettext("Token"),width:"200px"},{id:"value",label:l.$gettext("Value")}],isCheckable:!1},!1))],1)]},proxy:!0}])})},e=[],c=o("./js/stores/index.ts"),a={props:{tokens:{type:Array,required:!0,default:()=>[]}},data:()=>({search:"",hideEmpty:!0}),computed:{filtered(){const g=u=>!this.hideEmpty||u.value,l=(u,t)=>u.toLowerCase().includes(t.toLowerCase()),p=({value:u,token:t})=>this.search?l(t,this.search)||l(u,this.search):!0;return this.tokens.filter(g).filter(p)},...(0,c.Kc)(["client"])}},m=a,h=o("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),j=(0,h.Z)(m,s,e,!1,null,null,null),y=j.exports},"./js/pages/admin/custom-httpd/view.vue":function(_,f,o){"use strict";o.r(f),o.d(f,{default:function(){return p}});var s=function(){var t=this,i=t._self._c;return i("app-page",{attrs:{id:"custom-httpd-domain",actions:[{handler:()=>t.$router.push(`/admin/custom-httpd/domain/${t.dom}/${t.file}/customize`),icon:"#console",label:t.$gettext("Customize")}]},scopedSlots:t._u([{key:"page:title",fn:function(){return[i("ui-grid",[i("span",{domProps:{textContent:t._s(t.$gettext("View Domain Configuration"))}}),t._v(" "),t.$api.config.error?i("ui-badge",{attrs:{theme:"danger",size:"big"}},[i("span",{domProps:{textContent:t._s(t.$gettext("Syntax Error"))}})]):t._e()],1)]},proxy:!0},{key:"default",fn:function(){return[i("app-page-section",{scopedSlots:t._u([{key:"section:title",fn:function(){return[i("span",{domProps:{textContent:t._s(t.$gettextInterpolate(t.$gettext("Contents of the %{ filename } file for %{ domain }"),{domain:t.$p6e.toU(t.dom),filename:t.filename}))}})]},proxy:!0}])},[t._v(" "),i("ol",{staticClass:"config limited"},t._l(t.$api.config.data,function(n,r){return i("li",{key:`${r}-${n}`,staticClass:"line"},[i("pre",{staticClass:"line-content",domProps:{textContent:t._s(n)}})])}),0)]),t._v(" "),t.$api.config.error?i("app-page-section",{scopedSlots:t._u([{key:"section:title",fn:function(){return[i("span",{domProps:{textContent:t._s(t.$gettext("Configuration Check"))}})]},proxy:!0}],null,!1,963958610)},[t._v(" "),i("pre",{staticClass:"configuration-check",domProps:{textContent:t._s(t.$api.config.test)}})]):t._e(),t._v(" "),i("app-page-section",{scopedSlots:t._u([{key:"section:title",fn:function(){return[i("span",{domProps:{textContent:t._s(t.$gettext("Templates"))}})]},proxy:!0}])},[t._v(" "),i("table",{staticClass:"table table-elem"},[i("tbody",t._l(t.$api.config.templates,function(n){return i("tr",{key:n.name_short,staticClass:"table-row"},[i("td",{attrs:{width:"1%"}},[i("ui-link",{on:{click:function(r){return t.showTemplate(n)}}},[t._v(`
                                `+t._s(n.name)+`
                            `)])],1),t._v(" "),i("td",[i("ui-link",{attrs:{name:"admin/custom-httpd/diff",params:{name:n.name_short}}},[n.custom?i("ui-badge",{attrs:{theme:"primary"}},[i("span",{domProps:{textContent:t._s(t.$gettext("Custom"))}})]):t._e()],1)],1)])}),0)])]),t._v(" "),i("ui-dialog",{attrs:{id:"SHOW_TEMPLATE_DIALOG",size:"normal"},scopedSlots:t._u([{key:"title",fn:function(){return[i("span",{staticClass:"lowercase",domProps:{textContent:t._s(t.template.name_short)}})]},proxy:!0},{key:"content",fn:function(){return[t.template.data?i("input-text-editor",{attrs:{value:t.template.data.join(`
`),"read-only":"","disable-themes":"","disable-modes":""}}):t._e()]},proxy:!0}])}),t._v(" "),i("available-tokens-dialog",{attrs:{tokens:t.$api.config.tokens}})]},proxy:!0},{key:"bottom:links",fn:function(){return[i("ui-link",{attrs:{bullet:""},on:{click:function(n){t.$dialog("VIEW_ALL_AVAILABLE_TOKENS").open()}}},[i("span",{domProps:{textContent:t._s(t.$gettext("View All Available Tokens"))}})])]},proxy:!0}])})},e=[],c=o("./js/api/commands/admin/httpd.js"),a=o("./js/pages/admin/custom-httpd/_dialogs/available-tokens-dialog.vue"),m=o("./js/components/local/inputs/input-text-editor.vue"),h={preload:({dom:u,file:t})=>(0,c.Yy)({domain:u,proxy:t==="nginx_proxy"}),api:[{command:c.Yy,bind:"config"}],components:{InputTextEditor:m.Z,AvailableTokensDialog:a.Z},props:{dom:{type:String,required:!0},file:{type:String,required:!0,validator:u=>["nginx_proxy","nginx","httpd","openlitespeed"].includes(u)}},data(){return{template:{}}},computed:{filename(){return this.file==="nginx_proxy"?"nginx.conf":`${this.file}.conf`}},methods:{showTemplate(u){this.template=u,this.$dialog("SHOW_TEMPLATE_DIALOG").open()}}},j=h,y=o("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custom-httpd/view.vue?vue&type=style&index=0&id=5c1a7204&prod&lang=scss&scoped=true&"),g=o("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),l=(0,g.Z)(j,s,e,!1,null,"5c1a7204",null),p=l.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&":function(_,f,o){var s=o("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&");s.__esModule&&(s=s.default),typeof s=="string"&&(s=[[_.id,s,""]]),s.locals&&(_.exports=s.locals);var e=o("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,c=e("bb557a88",s,!0,{})},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custom-httpd/view.vue?vue&type=style&index=0&id=5c1a7204&prod&lang=scss&scoped=true&":function(_,f,o){var s=o("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custom-httpd/view.vue?vue&type=style&index=0&id=5c1a7204&prod&lang=scss&scoped=true&");s.__esModule&&(s=s.default),typeof s=="string"&&(s=[[_.id,s,""]]),s.locals&&(_.exports=s.locals);var e=o("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,c=e("603d4fc2",s,!0,{})}}]);
