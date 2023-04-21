(self.webpackChunk=self.webpackChunk||[]).push([[6684],{"../node_modules/date-fns/esm/formatDistance/index.js":function(M,v,s){"use strict";s.d(v,{Z:function(){return f}});var i=s("../node_modules/date-fns/esm/_lib/defaultOptions/index.js"),a=s("../node_modules/date-fns/esm/toDate/index.js"),m=s("../node_modules/date-fns/esm/_lib/requiredArgs/index.js");function r(e,t){(0,m.Z)(2,arguments);var n=(0,a.Z)(e),o=(0,a.Z)(t),u=n.getTime()-o.getTime();return u<0?-1:u>0?1:u}function x(e,t){(0,m.Z)(2,arguments);var n=(0,a.Z)(e),o=(0,a.Z)(t),u=n.getFullYear()-o.getFullYear(),g=n.getMonth()-o.getMonth();return u*12+g}function h(e){(0,m.Z)(1,arguments);var t=(0,a.Z)(e);return t.setHours(23,59,59,999),t}function S(e){(0,m.Z)(1,arguments);var t=(0,a.Z)(e),n=t.getMonth();return t.setFullYear(t.getFullYear(),n+1,0),t.setHours(23,59,59,999),t}function R(e){(0,m.Z)(1,arguments);var t=(0,a.Z)(e);return h(t).getTime()===S(t).getTime()}function A(e,t){(0,m.Z)(2,arguments);var n=(0,a.Z)(e),o=(0,a.Z)(t),u=r(n,o),g=Math.abs(x(n,o)),c;if(g<1)c=0;else{n.getMonth()===1&&n.getDate()>27&&n.setDate(30),n.setMonth(n.getMonth()-u*g);var N=r(n,o)===-u;R((0,a.Z)(e))&&g===1&&r(e,o)===1&&(N=!1),c=u*(g-Number(N))}return c===0?0:c}function Z(e,t){return(0,m.Z)(2,arguments),(0,a.Z)(e).getTime()-(0,a.Z)(t).getTime()}var O={ceil:Math.ceil,round:Math.round,floor:Math.floor,trunc:function(t){return t<0?Math.ceil(t):Math.floor(t)}},$="trunc";function E(e){return e?O[e]:O[$]}function I(e,t,n){(0,m.Z)(2,arguments);var o=Z(e,t)/1e3;return E(n==null?void 0:n.roundingMethod)(o)}var D=s("../node_modules/date-fns/esm/_lib/defaultLocale/index.js");function b(e,t){if(e==null)throw new TypeError("assign requires that input parameter not be null or undefined");for(var n in t)Object.prototype.hasOwnProperty.call(t,n)&&(e[n]=t[n]);return e}function P(e){return b({},e)}var d=s("../node_modules/date-fns/esm/_lib/getTimezoneOffsetInMilliseconds/index.js"),l=1440,_=2520,y=43200,T=86400;function f(e,t,n){var o,u;(0,m.Z)(2,arguments);var g=(0,i.j)(),c=(o=(u=n==null?void 0:n.locale)!==null&&u!==void 0?u:g.locale)!==null&&o!==void 0?o:D.Z;if(!c.formatDistance)throw new RangeError("locale must contain formatDistance property");var N=r(e,t);if(isNaN(N))throw new RangeError("Invalid time value");var p=b(P(n),{addSuffix:Boolean(n==null?void 0:n.addSuffix),comparison:N}),C,B;N>0?(C=(0,a.Z)(t),B=(0,a.Z)(e)):(C=(0,a.Z)(e),B=(0,a.Z)(t));var L=I(B,C),W=((0,d.Z)(B)-(0,d.Z)(C))/1e3,j=Math.round((L-W)/60),U;if(j<2)return n!=null&&n.includeSeconds?L<5?c.formatDistance("lessThanXSeconds",5,p):L<10?c.formatDistance("lessThanXSeconds",10,p):L<20?c.formatDistance("lessThanXSeconds",20,p):L<40?c.formatDistance("halfAMinute",0,p):L<60?c.formatDistance("lessThanXMinutes",1,p):c.formatDistance("xMinutes",1,p):j===0?c.formatDistance("lessThanXMinutes",1,p):c.formatDistance("xMinutes",j,p);if(j<45)return c.formatDistance("xMinutes",j,p);if(j<90)return c.formatDistance("aboutXHours",1,p);if(j<l){var X=Math.round(j/60);return c.formatDistance("aboutXHours",X,p)}else{if(j<_)return c.formatDistance("xDays",1,p);if(j<y){var G=Math.round(j/l);return c.formatDistance("xDays",G,p)}else if(j<T)return U=Math.round(j/y),c.formatDistance("aboutXMonths",U,p)}if(U=A(B,C),U<12){var H=Math.round(j/y);return c.formatDistance("xMonths",H,p)}else{var z=U%12,F=Math.floor(U/12);return z<3?c.formatDistance("aboutXYears",F,p):z<9?c.formatDistance("overXYears",F,p):c.formatDistance("almostXYears",F+1,p)}}},"./js/vue-globals/mixins/local/inputValidation.js":function(M,v,s){"use strict";s.r(v),s.d(v,{$inputValidation:function(){return m}});var i=s("./js/vue-globals/helpers.js"),a=s("./js/stores/index.ts");const m={inject:{groupID:{default:null},inputID:{default:null},validators:{default:()=>({})}},props:{id:{type:String,required:!1,default(){return this.inputID}},group:{type:String,required:!1,default(){return this.groupID}},novalidate:{type:Boolean,required:!1,default(){return!Object.keys(this.validators).length}}},computed:{validationStore(){return(0,a.oR)(PiniaStores.VALIDATION)},valid(){return this.validationStore.isValid(this.group,this.id)},errorState(){return!this.novalidate&&this.isUpdated&&!this.valid},isUpdated(){var r;const x=(r=this.validationStore.groups[this.group])==null?void 0:r[this.id];return typeof x=="undefined"?!1:x.updated}},methods:{$validate(r){this.id&&!this.novalidate&&this.validationStore.validate(this.groupID,this.id,r,this.validators)}},created(){if(!this.novalidate){const{validate:r}=this.$options;r&&this.$watch(r,(0,i.Ds)(this.$validate,{trailing:!0,leading:!1,delay:200}),{immediate:!0})}},destroyed(){this.novalidate||this.validationStore.deleteInput(this.group,this.id)}}},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&":function(){},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/file-editor.vue?vue&type=style&index=0&id=1e1d6491&prod&lang=scss&scoped=true&":function(){},"./js/composables/dateFilter.ts":function(M,v,s){"use strict";s.d(v,{W:function(){return x},f:function(){return m.f}});var i=s("../node_modules/ramda/es/index.js"),a=s("../node_modules/date-fns/esm/format/index.js"),m=s("./js/modules/date-formats.ts"),r=s("./js/modules/customizations/date-formats/default.ts");const x=i.WAo((h,S)=>{if(S)try{return(0,a.Z)(S,m.f.value[h])}catch(R){return console.warn(`Given ${h} format is incorrect:
${R.message}`),(0,a.Z)(S,r.d[h])}return""})},"./js/composables/filters.ts":function(M,v,s){"use strict";s.d(v,{Q0:function(){return I},aS:function(){return b},d5:function(){return D},eB:function(){return O},hT:function(){return A},kC:function(){return R},n9:function(){return E},zM:function(){return Z}});var i=s("../node_modules/date-fns/esm/formatDistance/index.js"),a=s("../node_modules/punycode/punycode.es6.js"),m=s("./js/composables/dateFilter.ts"),r=s("./js/composables/gettext.ts");const{$gettext:x,$ngettext:h,$gettextInterpolate:S}=(0,r.Z)(),R=d=>{var l;return d?((l=d.at(0))===null||l===void 0?void 0:l.toUpperCase())+d.slice(1):""},A=(d,l="datetime")=>(0,m.W)(l,d),Z=d=>(0,i.Z)(d,new Date),O=(d,l=1024)=>{const _=Number(d);if(!_)return"0 B";const y=["B","KB","MB","GB","TB","PB","EB","ZB","YB"],T=Math.floor(Math.log(_)/Math.log(l));return`${parseFloat((_/l**T).toFixed(2))} ${y[T]}`},$=d=>{try{return(0,a.xX)(d)}catch(l){return d}},E=d=>(0,a.xX)(d),I=d=>{if(!d||!d.includes("@"))return d;const[l,_]=d.split("@");return[l,$(_)].join("@")},D=d=>{if(d<60)return x("less than a minute");const l=Math.floor(d/60)%60,_=Math.floor(d/3600)%24,y=Math.floor(d/(3600*24)),T=[y?h("%{days} day","%{days} days",y):null,_?h("%{hours} hour","%{hours} hours",_):null,l?h("%{minutes} minute","%{minutes} minutes",l):null].filter(Boolean).join(", ");return S(T,{days:y,hours:_,minutes:l})},b=(d,l)=>d.length<=l?d:`${d.substring(0,l)}...`,P=()=>({capitalize:R,date:A,distanceFromNow:Z,humanReadableSize:O,p6eUnicode:E,p6eUnicodeEmail:I,formatUptime:D,truncateString:b})},"./js/components/local/inputs/input-text-editor.vue":function(M,v,s){"use strict";s.d(v,{Z:function(){return t}});var i=function(){var o=this,u=o._self._c;return u("div",{staticClass:"input-text-editor"},[o.$slots.header||o.$scopedSlots.header?u("div",{staticClass:"input-text-editor-header"},[o._t("header")],2):o._e(),o._v(" "),u("codemirror",{ref:"editor",attrs:{value:o.value,options:{lineNumbers:!0,readOnly:o.readOnly,mode:o.cmMode,theme:o.theme}},on:{input:function(g){return o.$emit("input",g)}}}),o._v(" "),!o.disableModes||!o.disableThemes?u("div",{staticClass:"input-text-editor-bottom-bar"},[o._t("bottom"),o._v(" "),u("span",{directives:[{name:"flex-item",rawName:"v-flex-item",value:{grow:!0},expression:"{ grow: true }"}]}),o._v(" "),o.disableModes?o._e():u("input-select",{staticClass:"input-text-editor-bottom-bar-select",attrs:{options:o.modes},scopedSlots:o._u([{key:"additions:left",fn:function(){return[u("ui-button",{attrs:{disabled:""}},[u("span",{domProps:{textContent:o._s(o.$gettext("Mode:"))}})])]},proxy:!0}],null,!1,42350692),model:{value:o.editorMode,callback:function(g){o.editorMode=g},expression:"editorMode"}}),o._v(" "),o.disableThemes?o._e():u("input-select",{staticClass:"input-text-editor-bottom-bar-select --wide",attrs:{options:o.themes},scopedSlots:o._u([{key:"additions:left",fn:function(){return[u("ui-button",{attrs:{disabled:""}},[u("span",{domProps:{textContent:o._s(o.$gettext("Theme:"))}})])]},proxy:!0}],null,!1,3964340662),model:{value:o.theme,callback:function(g){o.theme=g},expression:"theme"}})],2):o._e()],1)},a=[],m=s("../node_modules/vue-codemirror/dist/vue-codemirror.js"),r=s("../node_modules/codemirror/mode/javascript/javascript.js"),x=s("../node_modules/codemirror/mode/htmlmixed/htmlmixed.js"),h=s("../node_modules/codemirror/mode/css/css.js"),S=s("../node_modules/codemirror/mode/php/php.js"),R=s("../node_modules/codemirror/mode/perl/perl.js"),A=s("../node_modules/codemirror/mode/properties/properties.js"),Z=s("../node_modules/codemirror/mode/xml/xml.js"),O=s("../node_modules/codemirror/mode/sql/sql.js"),$=s("./js/modules/utils/index.js"),E=s("../node_modules/vue/dist/vue.common.prod.js"),I=s("./js/vue-globals/mixins/local/inputValidation.js"),D=s("./js/context/index.ts"),b=s("./js/modules/dark-mode.ts");const P=["default","base16-light","base16-dark","monokai","solarized"],d=["text","html","javascript","css","php","perl","ini","xml","sql","mysql","json"],l=n=>o=>n.includes(o);m.codemirror.beforeDestroy=void 0;var _={components:{codemirror:m.codemirror},mixins:[I.$inputValidation],validate:"value",props:{value:{type:String,required:!0,default:""},readOnly:{type:Boolean,required:!1,default:!1},mode:{type:String,required:!1,default:"text",validator:l(d)},disableModes:{type:Boolean,required:!1,default:!1},disableThemes:{type:Boolean,required:!1,default:!1}},data(){return{editorMode:this.mode,theme:"default"}},staticData:{modes:d,themes:P},computed:{cmMode(){switch(this.editorMode){case"json":return{name:"javascript",json:!0};case"mysql":return"sql";case"ini":return"properties";default:return this.editorMode}}},mounted(){(0,E.watch)(()=>D.T.options["code-editor/theme"],n=>{this.theme=n},{immediate:!0}),(0,b.Uu)(n=>{this.theme=n==="dark"?"base16-dark":D.T.options["code-editor/theme"]})}},y=_,T=s("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&"),f=s("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),e=(0,f.Z)(y,i,a,!1,null,null,null),t=e.exports},"./js/pages/admin/file-editor.vue":function(M,v,s){"use strict";s.r(v),s.d(v,{default:function(){return T}});var i=function(){var e=this,t=e._self._c;return t("app-page",{attrs:{id:"file-editor"},scopedSlots:e._u([{key:"default",fn:function(){return[e.file?t("app-page-section",[t("input-text-editor",{scopedSlots:e._u([{key:"header",fn:function(){return[e._v(`
                    `+e._s(e.file)+`
                `)]},proxy:!0}]),model:{value:e.text,callback:function(n){e.text=n},expression:"text"}})],1):t("app-page-section",[t("ui-r-table",e._b({attrs:{"disable-pagination":""},scopedSlots:e._u([{key:"col:file",fn:function({file:n}){return[t("ui-link",{attrs:{name:"admin/file-editor",query:{file:n}}},[e._v(`
                        `+e._s(n)+`
                    `)])]}},{key:"col:size",fn:function({size:n,exists:o}){return[t("span",{domProps:{textContent:e._s(o?e.humanReadableSize(n):e.$gettext("Does not exist"))}})]}}],null,!1,2348871994)},"ui-r-table",{rows:e.files,columns:[{id:"file",label:e.$gettext("File"),grow:!0,editable:!1},{id:"size",label:e.$gettext("Size")}],isCheckable:!1,verticalLayout:e.clientStore.isPhone},!1))],1),e._v(" "),t("root-auth-dialog",e._b({on:{confirmSave:e.save,close:function(n){return e.$router.push({name:"admin/file-editor",query:{}})}}},"root-auth-dialog",{file:e.file,text:e.text},!1))]},proxy:!0},{key:"footer:buttons",fn:function(){return[e.file?t("ui-button",{attrs:{theme:"safe"},on:{click:e.requestAuthAndSave}},[t("span",{domProps:{textContent:e._s(e.$gettext("Save"))}})]):e._e()]},proxy:!0}])})},a=[],m=s("./js/stores/index.ts"),r=s("./js/api/command/index.js");const x="/CMD_ADMIN_FILE_EDITOR",h=r.Z.get({id:"FILE_DATA",url:x,schema:{file:r.Z.OPTIONAL_STRING},after:f=>f.flow(f.moveProp({FILEDATA:"data",FILES:"files",READONLY:"readOnly",REQUIRE_ROOT_AUTH:"auth"}),f.mapProps({auth:f.convert.toAppBoolean,readOnly:f.convert.toAppBoolean,files:f.flow(f.mapValues((e,t)=>({...e,file:t})),f.toArray,f.mapArrayProps({exists:f.isEqual("1"),size:f.convert.toAppNumber})),data:f.convert.toAppText}))}),S=r.Z.post({url:x,params:{action:"save"},schema:{file:r.Z.REQUIRED_STRING,text:r.Z.REQUIRED_STRING}}),R=r.Z.post({url:x,params:{action:"save",authenticate:!0},schema:{rootpass:r.Z.REQUIRED_STRING,file:r.Z.REQUIRED_STRING,text:r.Z.REQUIRED_STRING}});var A=s("./js/components/local/inputs/input-text-editor.vue"),Z=s("./js/composables/filters.ts"),O=function(){var e=this,t=e._self._c;return t("ui-dialog",{attrs:{id:"ROOT_AUTH_DIALOG",theme:"danger",title:e.$gettext("Authenticate"),"no-close-btn":"","no-close-icon":"","no-auto-close":""},on:{"dialog:close":function(n){e.rootpass=""}},scopedSlots:e._u([{key:"content",fn:function(){return[t("ui-form-element",{attrs:{vertical:"",group:"rootAuth",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("This file is tagged as secure. Root password required to edit"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-password",{attrs:{autocomplete:!1},model:{value:e.rootpass,callback:function(n){e.rootpass=n},expression:"rootpass"}})]},proxy:!0}])})]},proxy:!0},{key:"buttons",fn:function(){return[t("ui-button",{attrs:{theme:"danger","validate-group":"rootAuth"},on:{click:e.auth}},[t("span",{domProps:{textContent:e._s(e.$gettext("Authenticate"))}})]),e._v(" "),t("ui-button",{attrs:{theme:"neutral"},on:{click:function(n){return e.$emit("close")}}},[t("span",{domProps:{textContent:e._s(e.$gettext("Back"))}})])]},proxy:!0}])})},$=[],E={props:{file:{type:String,default:""},text:{type:String,default:""}},data:()=>({rootpass:""}),methods:{async auth(){await R({file:this.file,text:this.text,rootpass:this.rootpass})&&(this.$emit("confirmSave"),this.$dialog("ROOT_AUTH_DIALOG").close())}}},I=E,D=s("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),b=(0,D.Z)(I,O,$,!1,null,null,null),P=b.exports,d={preload:h,components:{RootAuthDialog:P,InputTextEditor:A.Z},async beforeRouteUpdate(f,e,t){await h(f.query),this.text=this.data,this.$dialog("ROOT_AUTH_DIALOG").close(),t()},data(){return{text:""}},api:[{command:h,bind:"data"}],computed:{data(){return this.$api.data.data},files(){return this.$api.data.files},auth(){return this.$api.data.auth},file(){return this.$route.query.file},...(0,m.Kc)(["client"])},mounted(){this.text=this.data},methods:{humanReadableSize:Z.eB,requestAuthAndSave(){this.auth?this.$dialog("ROOT_AUTH_DIALOG").open():this.save()},async save(){await S({file:this.file,text:this.text})&&this.$router.push({name:"admin/file-editor"})}}},l=d,_=s("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/file-editor.vue?vue&type=style&index=0&id=1e1d6491&prod&lang=scss&scoped=true&"),y=(0,D.Z)(l,i,a,!1,null,"1e1d6491",null),T=y.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&":function(M,v,s){var i=s("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&");i.__esModule&&(i=i.default),typeof i=="string"&&(i=[[M.id,i,""]]),i.locals&&(M.exports=i.locals);var a=s("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,m=a("bb557a88",i,!0,{})},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/file-editor.vue?vue&type=style&index=0&id=1e1d6491&prod&lang=scss&scoped=true&":function(M,v,s){var i=s("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/file-editor.vue?vue&type=style&index=0&id=1e1d6491&prod&lang=scss&scoped=true&");i.__esModule&&(i=i.default),typeof i=="string"&&(i=[[M.id,i,""]]),i.locals&&(M.exports=i.locals);var a=s("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,m=a("150da780",i,!0,{})}}]);