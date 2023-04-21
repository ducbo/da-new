(self.webpackChunk=self.webpackChunk||[]).push([[7922],{"./js/api/commands/subdomains.js":function(p,r,o){"use strict";o.d(r,{AL:function(){return f},DG:function(){return a},HB:function(){return l},UZ:function(){return c},mz:function(){return g},xs:function(){return h}});var e=o("./js/api/command/index.js");const a=e.Z.get({id:"GET_SUBDOMAINS",url:"/CMD_SUBDOMAIN",schema:{domain:e.Z.DOMAIN,...e.Z.PAGINATION},after:n=>n.flow(n.moveProp("subdomains","rows"),n.moveProp("allow_subdomain_docroot_override","docroot"),n.processTableInfo("rows"),n.mapProps({awstats:i=>i!=="0",webalizer:n.isEqual("1"),docroot:n.isEqual("1"),has_php_selector:n.isEqual("yes"),rows:n.flow(n.toArray,n.mapArray(n.moveProp("subdomain_docroot_override","docroot")),n.mapArrayProps({bandwidth:n.convert.toAppNumber,stats:n.mapProps({webalizer_only:n.convert.toAppBoolean}),docroot:i=>{if(i&&Object.keys(i).length){if(typeof i.php1_select!="undefined"){const{options:x,value:m}=n.toSelect(i.php1_select);return{public_html:i.public_html,private_html:i.private_html,php_labels:x,php1_select:m}}return i}return!1}}))}))}),c=e.Z.post({url:"/CMD_SUBDOMAIN",params:{action:"create"},schema:{domain:e.Z.DOMAIN,subdomain:e.Z.REQUIRED_STRING,public_html:e.Z.OPTIONAL_STRING}}),l=e.Z.select({url:"/CMD_SUBDOMAIN",params:{action:"delete"},domain:!0,body:{contents:e.Z.REQUIRED_BOOL}}),h=e.Z.get({id:"GET_SUBDOMAIN_LOG",url:"/CMD_SHOW_LOG",params:{json:null},accept:"text/plain",schema:{domain:e.Z.DOMAIN,type:e.Z.REQUIRED_STRING,subdomain:e.Z.REQUIRED_STRING,lines:e.Z.OPTIONAL_STRING},after:n=>n.flow(n.convert.toLines,i=>i.slice(0,-1))}),g=e.Z.post({url:"/CMD_SUBDOMAIN",params:{action:"document_root_override"},domain:!0,schema:{subdomain:e.Z.REQUIRED_STRING,public_html:e.Z.OPTIONAL_STRING}}),f=e.Z.post({url:"/CMD_SUBDOMAIN",domain:!0,params:{action:"php_selector"},schema:{subdomain:e.Z.REQUIRED_STRING,php1_select:e.Z.REQUIRED_STRING}}),b=e.Z.get({url:"/CMD_SUBDOMAIN",id:"SUBDOMAIN_DATA",domain:!0,params:{action:"show_docroot_override"},schema:{subdomain:e.Z.REQUIRED_STRING},after:n=>n.flow(n.project({has_php_selector:"has_php_selector",http:"public_html",https:"private_html",php:"php1_select"}),n.mapProps({php:n.toSelect,has_php_selector:n.isEqual("yes")}))})},"./js/vue-globals/mixins/local/inputValidation.js":function(p,r,o){"use strict";o.r(r),o.d(r,{$inputValidation:function(){return c}});var e=o("./js/vue-globals/helpers.js"),a=o("./js/stores/index.ts");const c={inject:{groupID:{default:null},inputID:{default:null},validators:{default:()=>({})}},props:{id:{type:String,required:!1,default(){return this.inputID}},group:{type:String,required:!1,default(){return this.groupID}},novalidate:{type:Boolean,required:!1,default(){return!Object.keys(this.validators).length}}},computed:{validationStore(){return(0,a.oR)(PiniaStores.VALIDATION)},valid(){return this.validationStore.isValid(this.group,this.id)},errorState(){return!this.novalidate&&this.isUpdated&&!this.valid},isUpdated(){var l;const h=(l=this.validationStore.groups[this.group])==null?void 0:l[this.id];return typeof h=="undefined"?!1:h.updated}},methods:{$validate(l){this.id&&!this.novalidate&&this.validationStore.validate(this.groupID,this.id,l,this.validators)}},created(){if(!this.novalidate){const{validate:l}=this.$options;l&&this.$watch(l,(0,e.Ds)(this.$validate,{trailing:!0,leading:!1,delay:200}),{immediate:!0})}},destroyed(){this.novalidate||this.validationStore.deleteInput(this.group,this.id)}}},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&":function(){},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/subdomains/logs.vue?vue&type=style&index=0&id=43e63466&prod&lang=scss&scoped=true&":function(){},"./js/components/local/inputs/input-text-editor.vue":function(p,r,o){"use strict";o.d(r,{Z:function(){return P}});var e=function(){var t=this,u=t._self._c;return u("div",{staticClass:"input-text-editor"},[t.$slots.header||t.$scopedSlots.header?u("div",{staticClass:"input-text-editor-header"},[t._t("header")],2):t._e(),t._v(" "),u("codemirror",{ref:"editor",attrs:{value:t.value,options:{lineNumbers:!0,readOnly:t.readOnly,mode:t.cmMode,theme:t.theme}},on:{input:function(_){return t.$emit("input",_)}}}),t._v(" "),!t.disableModes||!t.disableThemes?u("div",{staticClass:"input-text-editor-bottom-bar"},[t._t("bottom"),t._v(" "),u("span",{directives:[{name:"flex-item",rawName:"v-flex-item",value:{grow:!0},expression:"{ grow: true }"}]}),t._v(" "),t.disableModes?t._e():u("input-select",{staticClass:"input-text-editor-bottom-bar-select",attrs:{options:t.modes},scopedSlots:t._u([{key:"additions:left",fn:function(){return[u("ui-button",{attrs:{disabled:""}},[u("span",{domProps:{textContent:t._s(t.$gettext("Mode:"))}})])]},proxy:!0}],null,!1,42350692),model:{value:t.editorMode,callback:function(_){t.editorMode=_},expression:"editorMode"}}),t._v(" "),t.disableThemes?t._e():u("input-select",{staticClass:"input-text-editor-bottom-bar-select --wide",attrs:{options:t.themes},scopedSlots:t._u([{key:"additions:left",fn:function(){return[u("ui-button",{attrs:{disabled:""}},[u("span",{domProps:{textContent:t._s(t.$gettext("Theme:"))}})])]},proxy:!0}],null,!1,3964340662),model:{value:t.theme,callback:function(_){t.theme=_},expression:"theme"}})],2):t._e()],1)},a=[],c=o("../node_modules/vue-codemirror/dist/vue-codemirror.js"),l=o("../node_modules/codemirror/mode/javascript/javascript.js"),h=o("../node_modules/codemirror/mode/htmlmixed/htmlmixed.js"),g=o("../node_modules/codemirror/mode/css/css.js"),f=o("../node_modules/codemirror/mode/php/php.js"),b=o("../node_modules/codemirror/mode/perl/perl.js"),n=o("../node_modules/codemirror/mode/properties/properties.js"),i=o("../node_modules/codemirror/mode/xml/xml.js"),x=o("../node_modules/codemirror/mode/sql/sql.js"),m=o("./js/modules/utils/index.js"),s=o("../node_modules/vue/dist/vue.common.prod.js"),d=o("./js/vue-globals/mixins/local/inputValidation.js"),v=o("./js/context/index.ts"),S=o("./js/modules/dark-mode.ts");const R=["default","base16-light","base16-dark","monokai","solarized"],y=["text","html","javascript","css","php","perl","ini","xml","sql","mysql","json"],I=j=>t=>j.includes(t);c.codemirror.beforeDestroy=void 0;var N={components:{codemirror:c.codemirror},mixins:[d.$inputValidation],validate:"value",props:{value:{type:String,required:!0,default:""},readOnly:{type:Boolean,required:!1,default:!1},mode:{type:String,required:!1,default:"text",validator:I(y)},disableModes:{type:Boolean,required:!1,default:!1},disableThemes:{type:Boolean,required:!1,default:!1}},data(){return{editorMode:this.mode,theme:"default"}},staticData:{modes:y,themes:R},computed:{cmMode(){switch(this.editorMode){case"json":return{name:"javascript",json:!0};case"mysql":return"sql";case"ini":return"properties";default:return this.editorMode}}},mounted(){(0,s.watch)(()=>v.T.options["code-editor/theme"],j=>{this.theme=j},{immediate:!0}),(0,S.Uu)(j=>{this.theme=j==="dark"?"base16-dark":v.T.options["code-editor/theme"]})}},D=N,E=o("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&"),O=o("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),M=(0,O.Z)(D,e,a,!1,null,null,null),P=M.exports},"./js/pages/user/subdomains/logs.vue":function(p,r,o){"use strict";o.r(r),o.d(r,{default:function(){return x}});var e=function(){var s=this,d=s._self._c;return d("app-page",{attrs:{id:"subdomain-log"}},[d("app-page-section",[d("div",{directives:[{name:"gutter",rawName:"v-gutter",value:1,expression:"1"}],staticClass:"filters"},[d("ui-form-element",{attrs:{underline:s.show==="lines"},scopedSlots:s._u([{key:"title",fn:function(){return[d("span",{domProps:{textContent:s._s(s.$gettext("Show"))}})]},proxy:!0},{key:"content",fn:function(){return[d("div",{directives:[{name:"gutter",rawName:"v-gutter",value:[0,2],expression:"[0, 2]"}]},[d("input-radio",{attrs:{value:"full"},on:{change:s.loadLog},model:{value:s.show,callback:function(v){s.show=v},expression:"show"}},[d("span",{domProps:{textContent:s._s(s.$gettext("Full Log"))}})]),s._v(" "),d("input-radio",{attrs:{value:"lines"},on:{change:s.loadLog},model:{value:s.show,callback:function(v){s.show=v},expression:"show"}},[d("span",{domProps:{textContent:s._s(s.$gettext("Tail"))}})])],1)]},proxy:!0}])}),s._v(" "),d("transition",{attrs:{name:"fade"}},[s.show==="lines"?d("ui-form-element",{attrs:{vertical:s.clientStore.isPhone,underline:!1},scopedSlots:s._u([{key:"title",fn:function(){return[d("span",{domProps:{textContent:s._s(s.$gettext("Number of lines to show"))}})]},proxy:!0},{key:"content",fn:function(){return[d("ui-grid",{attrs:{column:s.clientStore.isPhone,cross:s.clientStore.isPhone?"stretch":"center"}},[d("input-text",{attrs:{number:""},model:{value:s.lines,callback:function(v){s.lines=v},expression:"lines"}}),s._v(" "),d("ui-button",{attrs:{theme:"safe",size:"normal"},on:{click:s.loadLog}},[d("span",{domProps:{textContent:s._s(s.$gettext("Reload Log"))}})])],1)]},proxy:!0}],null,!1,2114083932)}):s._e()],1)],1),s._v(" "),d("input-text-editor",{attrs:{value:s.log,"read-only":"","disable-modes":""},scopedSlots:s._u([{key:"header",fn:function(){return[d("div",{directives:[{name:"flex",rawName:"v-flex",value:{cross:"center",main:"between"},expression:`{
                        cross: 'center',
                        main: 'between',
                    }`}]},[s._v(`
                    `+s._s(s.subdomain)+"."+s._s(s.$domainUnicode)+`
                    `),d("ui-button-link",{attrs:{size:"small",theme:"light",href:s.rawLink,target:"_blank"}},[d("span",{domProps:{textContent:s._s(s.$gettext("raw"))}})])],1)]},proxy:!0}])})],1)],1)},a=[],c=o("./js/stores/index.ts"),l=o("./js/api/commands/subdomains.js"),h=o("./js/components/local/inputs/input-text-editor.vue"),g={components:{InputTextEditor:h.Z},preload:m=>(0,l.xs)({subdomain:m.subdomain,type:m.type==="usage"?"log":"error",lines:"100"}),api:[{command:l.xs,bind:"log"}],props:{subdomain:{type:String,required:!0},type:{type:String,required:!0}},data:()=>({lines:"100",show:"lines"}),computed:{rawLink(){const m=this.type==="usage"?"log":"error",s=`/CMD_SHOW_LOG?domain=${this.$domain}&type=${m}&subdomain=${this.subdomain}`;return this.show==="lines"?`${s}&lines=${this.lines}`:s},log(){return this.$api.log.join(`
`)},...(0,c.Kc)(["client"])},methods:{loadLog(){const m=this.type==="usage"?"log":"error";(0,l.xs)({domain:this.$domain,subdomain:this.subdomain,type:m,lines:this.show==="lines"?this.lines:null})}}},f=g,b=o("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/subdomains/logs.vue?vue&type=style&index=0&id=43e63466&prod&lang=scss&scoped=true&"),n=o("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),i=(0,n.Z)(f,e,a,!1,null,"43e63466",null),x=i.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&":function(p,r,o){var e=o("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&");e.__esModule&&(e=e.default),typeof e=="string"&&(e=[[p.id,e,""]]),e.locals&&(p.exports=e.locals);var a=o("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,c=a("bb557a88",e,!0,{})},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/subdomains/logs.vue?vue&type=style&index=0&id=43e63466&prod&lang=scss&scoped=true&":function(p,r,o){var e=o("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/subdomains/logs.vue?vue&type=style&index=0&id=43e63466&prod&lang=scss&scoped=true&");e.__esModule&&(e=e.default),typeof e=="string"&&(e=[[p.id,e,""]]),e.locals&&(p.exports=e.locals);var a=o("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,c=a("7a879957",e,!0,{})}}]);