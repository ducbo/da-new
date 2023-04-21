(self.webpackChunk=self.webpackChunk||[]).push([[2399],{"./js/vue-globals/mixins/local/inputValidation.js":function(h,p,t){"use strict";t.r(p),t.d(p,{$inputValidation:function(){return u}});var l=t("./js/vue-globals/helpers.js"),v=t("./js/stores/index.ts");const u={inject:{groupID:{default:null},inputID:{default:null},validators:{default:()=>({})}},props:{id:{type:String,required:!1,default(){return this.inputID}},group:{type:String,required:!1,default(){return this.groupID}},novalidate:{type:Boolean,required:!1,default(){return!Object.keys(this.validators).length}}},computed:{validationStore(){return(0,v.oR)(PiniaStores.VALIDATION)},valid(){return this.validationStore.isValid(this.group,this.id)},errorState(){return!this.novalidate&&this.isUpdated&&!this.valid},isUpdated(){var i;const j=(i=this.validationStore.groups[this.group])==null?void 0:i[this.id];return typeof j=="undefined"?!1:j.updated}},methods:{$validate(i){this.id&&!this.novalidate&&this.validationStore.validate(this.groupID,this.id,i,this.validators)}},created(){if(!this.novalidate){const{validate:i}=this.$options;i&&this.$watch(i,(0,l.Ds)(this.$validate,{trailing:!0,leading:!1,delay:200}),{immediate:!0})}},destroyed(){this.novalidate||this.validationStore.deleteInput(this.group,this.id)}}},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&":function(){},"./js/components/local/inputs/input-text-editor.vue":function(h,p,t){"use strict";t.d(p,{Z:function(){return c}});var l=function(){var e=this,m=e._self._c;return m("div",{staticClass:"input-text-editor"},[e.$slots.header||e.$scopedSlots.header?m("div",{staticClass:"input-text-editor-header"},[e._t("header")],2):e._e(),e._v(" "),m("codemirror",{ref:"editor",attrs:{value:e.value,options:{lineNumbers:!0,readOnly:e.readOnly,mode:e.cmMode,theme:e.theme}},on:{input:function(x){return e.$emit("input",x)}}}),e._v(" "),!e.disableModes||!e.disableThemes?m("div",{staticClass:"input-text-editor-bottom-bar"},[e._t("bottom"),e._v(" "),m("span",{directives:[{name:"flex-item",rawName:"v-flex-item",value:{grow:!0},expression:"{ grow: true }"}]}),e._v(" "),e.disableModes?e._e():m("input-select",{staticClass:"input-text-editor-bottom-bar-select",attrs:{options:e.modes},scopedSlots:e._u([{key:"additions:left",fn:function(){return[m("ui-button",{attrs:{disabled:""}},[m("span",{domProps:{textContent:e._s(e.$gettext("Mode:"))}})])]},proxy:!0}],null,!1,42350692),model:{value:e.editorMode,callback:function(x){e.editorMode=x},expression:"editorMode"}}),e._v(" "),e.disableThemes?e._e():m("input-select",{staticClass:"input-text-editor-bottom-bar-select --wide",attrs:{options:e.themes},scopedSlots:e._u([{key:"additions:left",fn:function(){return[m("ui-button",{attrs:{disabled:""}},[m("span",{domProps:{textContent:e._s(e.$gettext("Theme:"))}})])]},proxy:!0}],null,!1,3964340662),model:{value:e.theme,callback:function(x){e.theme=x},expression:"theme"}})],2):e._e()],1)},v=[],u=t("../node_modules/vue-codemirror/dist/vue-codemirror.js"),i=t("../node_modules/codemirror/mode/javascript/javascript.js"),j=t("../node_modules/codemirror/mode/htmlmixed/htmlmixed.js"),_=t("../node_modules/codemirror/mode/css/css.js"),R=t("../node_modules/codemirror/mode/php/php.js"),C=t("../node_modules/codemirror/mode/perl/perl.js"),$=t("../node_modules/codemirror/mode/properties/properties.js"),M=t("../node_modules/codemirror/mode/xml/xml.js"),I=t("../node_modules/codemirror/mode/sql/sql.js"),P=t("./js/modules/utils/index.js"),S=t("../node_modules/vue/dist/vue.common.prod.js"),o=t("./js/vue-globals/mixins/local/inputValidation.js"),s=t("./js/context/index.ts"),d=t("./js/modules/dark-mode.ts");const n=["default","base16-light","base16-dark","monokai","solarized"],a=["text","html","javascript","css","php","perl","ini","xml","sql","mysql","json"],y=r=>e=>r.includes(e);u.codemirror.beforeDestroy=void 0;var f={components:{codemirror:u.codemirror},mixins:[o.$inputValidation],validate:"value",props:{value:{type:String,required:!0,default:""},readOnly:{type:Boolean,required:!1,default:!1},mode:{type:String,required:!1,default:"text",validator:y(a)},disableModes:{type:Boolean,required:!1,default:!1},disableThemes:{type:Boolean,required:!1,default:!1}},data(){return{editorMode:this.mode,theme:"default"}},staticData:{modes:a,themes:n},computed:{cmMode(){switch(this.editorMode){case"json":return{name:"javascript",json:!0};case"mysql":return"sql";case"ini":return"properties";default:return this.editorMode}}},mounted(){(0,S.watch)(()=>s.T.options["code-editor/theme"],r=>{this.theme=r},{immediate:!0}),(0,d.Uu)(r=>{this.theme=r==="dark"?"base16-dark":s.T.options["code-editor/theme"]})}},b=f,D=t("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&"),g=t("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),N=(0,g.Z)(b,l,v,!1,null,null,null),c=N.exports},"./js/pages/reseller/customize-skin/css.vue":function(h,p,t){"use strict";t.r(p),t.d(p,{default:function(){return P}});var l=function(){var o=this,s=o._self._c,d=o._self._setupProxy;return s("app-page",{scopedSlots:o._u([{key:"default",fn:function(){return[s("app-page-section",[s("ui-tabs",{attrs:{tabs:d.styleBlocks},scopedSlots:o._u([o._l(d.styleBlocks,function(n){return{key:`tab:${n.id}`,fn:function(){return[s(d.InputTextEditor,{key:`${n.id}-styles`,attrs:{value:d.styles[n.id],"disable-modes":"",mode:"css"},on:{input:function(a){return d.setCSS(n.id,a)}},scopedSlots:o._u([{key:"header",fn:function(){return[o._v(`
                            `+o._s(n.header)+`
                        `)]},proxy:!0},{key:"bottom",fn:function(){return[s("div",[s("ui-button",{key:"save-changes-button",attrs:{disabled:d.styles[n.id]===d.module.data[n.id],theme:"primary"},on:{click:function(a){return d.saveCSS(n.id)}}},[s("span",{domProps:{textContent:o._s(d.$gettext("Save changes"))}})]),o._v(" "),s("ui-button",{directives:[{name:"margin",rawName:"v-margin:left",value:1,expression:"1",arg:"left"}],key:"reset-changes-button",attrs:{theme:"danger",disabled:d.module.data[n.id]===""},on:{click:function(a){return d.resetCSS(n.id)}}},[s("span",{domProps:{textContent:o._s(d.$gettext("Reset to defaults"))}})])],1)]},proxy:!0}],null,!0)})]},proxy:!0}})],null,!0)})],1)]},proxy:!0}])})},v=[],u=t("../node_modules/vue/dist/vue.common.prod.js"),i=t("../node_modules/ramda/es/index.js"),j=t("./js/components/local/inputs/input-text-editor.vue"),_=t("./js/composables/index.ts"),R=t("./js/stores/index.ts"),C=(0,u.defineComponent)({__name:"css",setup(S){const o=(0,R.oR)("customization"),{$gettext:s,$gettextInterpolate:d}=(0,_.st)(),n=(0,u.computed)(()=>o.modules.css),a=(0,u.ref)({...n.value.data}),y=(0,u.computed)(()=>({standard:s("Standard"),grid:s("Icons Grid"),sidebar:s("Sidebar"),standard2021:s("Refreshed")})),f=c=>d(s('Styles specific to "%{layout}" layout'),{layout:y.value[c]}),b=(0,u.computed)(()=>[{id:"shared",label:s("Shared CSS"),header:s("Shared CSS Styles (would be applied to all layouts)")},{id:"standard",label:s("Standard"),header:f("standard")},{id:"grid",label:s("Icons Grid"),header:f("grid")},{id:"sidebar",label:s("Sidebar"),header:f("sidebar")},{id:"standard2021",label:s("Refreshed"),header:f("standard2021")}]),D=(c,r)=>{a.value[c]=r},g=async c=>{const r={...n.value.data};r[c]=a.value[c],i.$6P(i.xbD,i.VO0(r))?a.value={...await o.resetModule("css")}:(o.updateModule("css",r),o.saveModule("css"))};return{__sfc:!0,store:o,$gettext:s,$gettextInterpolate:d,module:n,styles:a,layoutNames:y,getLayoutHeader:f,styleBlocks:b,setCSS:D,saveCSS:g,resetCSS:c=>{a.value[c]="",g(c)},InputTextEditor:j.Z}}}),$=C,M=t("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),I=(0,M.Z)($,l,v,!1,null,null,null),P=I.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&":function(h,p,t){var l=t("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&");l.__esModule&&(l=l.default),typeof l=="string"&&(l=[[h.id,l,""]]),l.locals&&(h.exports=l.locals);var v=t("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,u=v("bb557a88",l,!0,{})}}]);