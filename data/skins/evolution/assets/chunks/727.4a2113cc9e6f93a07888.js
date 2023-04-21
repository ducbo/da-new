(self.webpackChunk=self.webpackChunk||[]).push([[727],{"./js/api/commands/user/stats.js":function(j,v,s){"use strict";s.d(v,{Jr:function(){return S},Lm:function(){return u},Vb:function(){return P},e5:function(){return _},fy:function(){return h},gc:function(){return c},ji:function(){return E},vQ:function(){return p}});var e=s("./js/api/command/index.js"),i=s("./js/api/commands/converters/customItems.ts"),r=s("../node_modules/ramda/es/index.js");const g="/CMD_USER_STATS",f="/CMD_CHANGE_INFO",h=e.Z.get({id:"USER_STATS",url:g,params:{bytes:!0},domain:!0,pagination:!0,after:o=>o.flow(o.project({domains:"domains",stats:"stats","addons.webalizer":"webalizer","addons.awstats":"awstats",limitNotice:"stats",customItems:"custom_items"}),o.mapProps({stats:o.flow(o.deleteProp("info"),o.toArray,o.filter(d=>!!d.usage),o.transformObject(d=>({[d.setting]:{usage:d.usage||void 0,limit:d.max_usage||void 0}})),o.mapValues(d=>["ON","OFF"].includes(d.usage)?{usage:d.usage==="ON"}:typeof d.usage=="object"?{...d,usage:Object.values(d.usage)}:d),o.mapValues(d=>d.limit?o.toLimitedUsage(o.convert.toAppNumber)(d):d.usage),o.mapProps({awstats:o.flow(o.toSelect,o.getProp("value"))})),domains:o.toTable(o.mapArray(o.flow(d=>{const R=d.subdomains||d.settings.subdomains||[];return typeof d.settings.subdomains!="undefined"&&delete d.settings.subdomains,d.subdomains=R,d},o.mapProps({bandwidth:o.mapProp("usage",o.convert.toAppNumber),quota:o.convert.toAppNumber,log_usage:o.convert.toAppNumber,nsubdomains:o.convert.toAppNumber,suspended:o.convert.toAppBoolean,settings:o.mapValues(o.convert.toAppBoolean)})))),addons:o.flow(o.toArray,o.mapArray(o.isEqual("1")),o.reduce((d,R)=>d||R,!1)),limitNotice:d=>{const R=Object.values(d).find(N=>N.setting==="send_usage_message");if(!R)return!1;const I=R.max_usage,{value:T}=o.toSelect(R.usage);return{defaultValue:I,value:T}},customItems:r.zGw(r.yAE({}),r.UID(i.CR),r.hXT(d=>d.value||d.type==="checkbox"),r.VO0)}))}),_=e.Z.get({id:"STATS_STATUS",url:g,domain:!0,after:o=>o.flow(o.project({awstats:"awstats",awstatsOptions:"domain_awstats",webalizer:"webalizer"}),o.mapProp("awstats",d=>d!=="0"),o.mapProp("webalizer",o.isEqual("1")))}),u=e.Z.get({id:"WEBALIZER_REPORT",url:"/CMD_FILE_MANAGER",response:!1,params:{action:"exists"},schema:{domain:e.Z.DOMAIN,subdomain:e.Z.OPTIONAL_STRING},before:({domain:o,subdomain:d})=>({path:d?`/domains/${o}/stats/${d}/index.html`:`/domains/${o}/stats/index.html`,domain:null,subdomain:null}),after:()=>({exists:o})=>o==="1"}),c=e.Z.select({url:"/CMD_PUBLIC_STATS",params:{action:"public",json:!0},domain:!0,schema:{path:e.Z.REQUIRED_STRING}}),p=e.Z.select({url:"/CMD_PUBLIC_STATS",params:{action:"public",json:!0,unset:!0},schema:{path:e.Z.REQUIRED_STRING}}),a=e.Z.post({url:f,params:{json:!0},domain:!0,schema:{evalue:e.Z.OPTIONAL_STRING,nvalue:e.Z.OPTIONAL_STRING,lvalue:e.Z.OPTIONAL_STRING}}),t=e.Z.post({url:f,domain:!0}),n=t.extend({params:{name:!0},schema:{nvalue:e.Z.REQUIRED_STRING}}),m=t.extend({params:{email:!0},schema:{evalue:e.Z.REQUIRED_STRING}}),y=t.extend({params:{skin:!0},schema:{skinvalue:e.Z.REQUIRED_STRING}}),S=t.extend({params:{set_multiple:!0,send_usage_message:!0},schema:{nvalue:e.Z.OPTIONAL_STRING,evalue:e.Z.OPTIONAL_STRING,skinvalue:e.Z.OPTIONAL_STRING,lvalue:e.Z.OPTIONAL_STRING,awstatsvalue:e.Z.OPTIONAL_STRING,zvalue:e.Z.OPTIONAL_STRING},before:o=>({name:!!o.nvalue||null,email:!!o.evalue||null,skin:!!o.skinvalue||null,language:!!o.lvalue||null,awstats:!!o.awstatsvalue||null,zoom:!!o.zvalue||null})}),M=t.extend({params:{awstats:!0},schema:{awstatsvalue:e.Z.REQUIRED_STRING}}),E=e.Z.post({url:"/CMD_CHANGE_INFO",params:{update:!0}}),P=e.Z.get({id:"DOMAIN_LOG",url:"/CMD_SHOW_LOG",params:{json:null},accepts:"text/plain",domain:!0,schema:{type:e.Z.REQUIRED_STRING},after:o=>o.flow(d=>d.split(`
`),d=>d.slice(0,-1))})},"./js/vue-globals/mixins/local/inputValidation.js":function(j,v,s){"use strict";s.r(v),s.d(v,{$inputValidation:function(){return r}});var e=s("./js/vue-globals/helpers.js"),i=s("./js/stores/index.ts");const r={inject:{groupID:{default:null},inputID:{default:null},validators:{default:()=>({})}},props:{id:{type:String,required:!1,default(){return this.inputID}},group:{type:String,required:!1,default(){return this.groupID}},novalidate:{type:Boolean,required:!1,default(){return!Object.keys(this.validators).length}}},computed:{validationStore(){return(0,i.oR)(PiniaStores.VALIDATION)},valid(){return this.validationStore.isValid(this.group,this.id)},errorState(){return!this.novalidate&&this.isUpdated&&!this.valid},isUpdated(){var g;const f=(g=this.validationStore.groups[this.group])==null?void 0:g[this.id];return typeof f=="undefined"?!1:f.updated}},methods:{$validate(g){this.id&&!this.novalidate&&this.validationStore.validate(this.groupID,this.id,g,this.validators)}},created(){if(!this.novalidate){const{validate:g}=this.$options;g&&this.$watch(g,(0,e.Ds)(this.$validate,{trailing:!0,leading:!1,delay:200}),{immediate:!0})}},destroyed(){this.novalidate||this.validationStore.deleteInput(this.group,this.id)}}},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&":function(){},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/stats/log.vue?vue&type=style&index=0&id=3a436368&prod&lang=scss&scoped=true&":function(){},"./js/api/commands/converters/customItems.ts":function(j,v,s){"use strict";s.d(v,{CR:function(){return f}});var e=s("../node_modules/ramda/es/index.js"),i=s("./js/api/commands/converters/index.ts"),r=s("./js/api/commands/utils/transduce.ts"),g=s("./js/api/commands/converters/toSelectData.ts");const f=u=>{const c={name:u.name,type:u.type==="listbox"?"select":u.type,label:u.string,description:u.desc||"",value:u.type==="checkbox"?(0,i.sw)(u.checked||"no"):u.value||""};return c.type==="select"?e.BPw(c,(0,g.M1)(u.select||{})):c},h=u=>(0,r.vr)([(0,r.uD)(c=>/^item\d+val$/.test(c)),(0,r.r5)(c=>{const p=c,a=c.replace("val","txt"),t=u[p],n=u[a];return{[t]:n}})],Object.keys(u)),_=(u,c)=>e.qCK(a=>{const t={name:a.name,type:a.type==="listbox"?"select":a.type,description:a.desc||"",value:a.value||"",label:a.string};return a.type==="listbox"?(t.value=a.default,t.options=h(a)):a.type==="checkbox"&&(t.value=a.checked==="yes"),t},e.BPw({name:u}),(0,r.vr)([(0,r.r5)(a=>{const[t,n]=e.Vl2("=",a);return{[t]:n}})]),e.Vl2("&"))(c);v.ZP={fromObject:f,fromString:_}},"./js/api/commands/converters/index.ts":function(j,v,s){"use strict";s.d(v,{l$:function(){return p.ZP},t0:function(){return e.t0},S8:function(){return e.S8},ql:function(){return e.ql},sw:function(){return e.sw},Qu:function(){return e.Qu},He:function(){return e.He},M1:function(){return c.M1},sf:function(){return t},cc:function(){return u}});var e=s("./js/api/commands/converters/primitive.ts"),i=s("../node_modules/monet/dist/monet.js"),r=s("./js/api/commands/types.ts");const g=n=>typeof n=="object"?i.Either.Right(n):i.Either.Left(new Error("Passed param is not an object")),f=n=>typeof n.usage=="string"?i.Either.Right(n):i.Either.Left(new Error("usage property is required")),h=n=>({usage:(0,e.He)(n.usage),limit:(0,e.Qu)(n.limit)}),_=({usage:n,limit:m})=>{let y=r.H.Normal;const S=Math.floor(n/m*100);return S>=100?y=r.H.OverUsed:S>80&&(y=r.H.AlmostUsed),{usage:n,limit:m,status:y}},u=n=>{const m=i.Either.Right(n).flatMap(g).flatMap(f).map(h).map(_);if(m.isLeft())throw m.left();return m.right()};var c=s("./js/api/commands/converters/toSelectData.ts"),p=s("./js/api/commands/converters/customItems.ts"),a=s("../node_modules/ramda/es/index.js");const t=n=>m=>{const{info:y}=m,S=a.CEd(["info"],m);return{columns:y.columns,rowsCount:Number(y.rows),rows:a.UID(n,a.VO0(S))}}},"./js/api/commands/converters/toSelectData.ts":function(j,v,s){"use strict";s.d(v,{M1:function(){return _}});var e=s("../node_modules/monet/dist/monet.js"),i=s.n(e),r=s("./js/api/commands/utils/transduce.ts"),g=s("../node_modules/ramda/es/index.js");const f=u=>e.Maybe.Some(u).flatMap(c=>{const p=c.find(a=>a.selected==="yes");return p?e.Maybe.Some(p):e.Maybe.None()}).flatMap(c=>e.Maybe.fromNull(c.value)).orSome(""),h=(0,r.vr)([(0,r.r5)(u=>({[u.value]:u.text}))]),_=u=>{const c=(0,g.VO0)(u);return{value:f(c),options:h(c)}}},"./js/api/commands/types.ts":function(j,v,s){"use strict";s.d(v,{H:function(){return e}});var e;(function(i){i.Normal="normal",i.AlmostUsed="almost_used",i.OverUsed="overused"})(e||(e={}))},"./js/api/commands/utils/transduce.ts":function(j,v,s){"use strict";s.d(v,{Re:function(){return g},r5:function(){return i},uD:function(){return r},vr:function(){return c},zh:function(){return _}});var e=s("../node_modules/ramda/es/index.js");const i=p=>a=>(t,n)=>{const m=p(n);return a(t,m)},r=p=>a=>(t,n)=>p(n)?a(t,n):t,g=(p,a)=>(p.push(a),p),f=(p,a)=>e.BPw(p,a),h=(p,a,t,n)=>{const m=e.qCK(...t);return n.reduce(m(a),p)},_=e.WAo(h),u=_([],g),c=_({},f)},"./js/components/local/inputs/input-text-editor.vue":function(j,v,s){"use strict";s.d(v,{Z:function(){return N}});var e=function(){var l=this,x=l._self._c;return x("div",{staticClass:"input-text-editor"},[l.$slots.header||l.$scopedSlots.header?x("div",{staticClass:"input-text-editor-header"},[l._t("header")],2):l._e(),l._v(" "),x("codemirror",{ref:"editor",attrs:{value:l.value,options:{lineNumbers:!0,readOnly:l.readOnly,mode:l.cmMode,theme:l.theme}},on:{input:function(O){return l.$emit("input",O)}}}),l._v(" "),!l.disableModes||!l.disableThemes?x("div",{staticClass:"input-text-editor-bottom-bar"},[l._t("bottom"),l._v(" "),x("span",{directives:[{name:"flex-item",rawName:"v-flex-item",value:{grow:!0},expression:"{ grow: true }"}]}),l._v(" "),l.disableModes?l._e():x("input-select",{staticClass:"input-text-editor-bottom-bar-select",attrs:{options:l.modes},scopedSlots:l._u([{key:"additions:left",fn:function(){return[x("ui-button",{attrs:{disabled:""}},[x("span",{domProps:{textContent:l._s(l.$gettext("Mode:"))}})])]},proxy:!0}],null,!1,42350692),model:{value:l.editorMode,callback:function(O){l.editorMode=O},expression:"editorMode"}}),l._v(" "),l.disableThemes?l._e():x("input-select",{staticClass:"input-text-editor-bottom-bar-select --wide",attrs:{options:l.themes},scopedSlots:l._u([{key:"additions:left",fn:function(){return[x("ui-button",{attrs:{disabled:""}},[x("span",{domProps:{textContent:l._s(l.$gettext("Theme:"))}})])]},proxy:!0}],null,!1,3964340662),model:{value:l.theme,callback:function(O){l.theme=O},expression:"theme"}})],2):l._e()],1)},i=[],r=s("../node_modules/vue-codemirror/dist/vue-codemirror.js"),g=s("../node_modules/codemirror/mode/javascript/javascript.js"),f=s("../node_modules/codemirror/mode/htmlmixed/htmlmixed.js"),h=s("../node_modules/codemirror/mode/css/css.js"),_=s("../node_modules/codemirror/mode/php/php.js"),u=s("../node_modules/codemirror/mode/perl/perl.js"),c=s("../node_modules/codemirror/mode/properties/properties.js"),p=s("../node_modules/codemirror/mode/xml/xml.js"),a=s("../node_modules/codemirror/mode/sql/sql.js"),t=s("./js/modules/utils/index.js"),n=s("../node_modules/vue/dist/vue.common.prod.js"),m=s("./js/vue-globals/mixins/local/inputValidation.js"),y=s("./js/context/index.ts"),S=s("./js/modules/dark-mode.ts");const M=["default","base16-light","base16-dark","monokai","solarized"],E=["text","html","javascript","css","php","perl","ini","xml","sql","mysql","json"],P=b=>l=>b.includes(l);r.codemirror.beforeDestroy=void 0;var o={components:{codemirror:r.codemirror},mixins:[m.$inputValidation],validate:"value",props:{value:{type:String,required:!0,default:""},readOnly:{type:Boolean,required:!1,default:!1},mode:{type:String,required:!1,default:"text",validator:P(E)},disableModes:{type:Boolean,required:!1,default:!1},disableThemes:{type:Boolean,required:!1,default:!1}},data(){return{editorMode:this.mode,theme:"default"}},staticData:{modes:E,themes:M},computed:{cmMode(){switch(this.editorMode){case"json":return{name:"javascript",json:!0};case"mysql":return"sql";case"ini":return"properties";default:return this.editorMode}}},mounted(){(0,n.watch)(()=>y.T.options["code-editor/theme"],b=>{this.theme=b},{immediate:!0}),(0,S.Uu)(b=>{this.theme=b==="dark"?"base16-dark":y.T.options["code-editor/theme"]})}},d=o,R=s("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&"),I=s("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),T=(0,I.Z)(d,e,i,!1,null,null,null),N=T.exports},"./js/pages/user/stats/log.vue":function(j,v,s){"use strict";s.r(v),s.d(v,{default:function(){return p}});var e=function(){var t=this,n=t._self._c;return n("app-page",{attrs:{id:"domain-log"},scopedSlots:t._u([{key:"page:title",fn:function(){return[n("span",{domProps:{textContent:t._s(t.pageTitle)}})]},proxy:!0},{key:"default",fn:function(){return[n("app-page-section",[n("div",{directives:[{name:"gutter",rawName:"v-gutter",value:1,expression:"1"}],staticClass:"filters"},[n("ui-form-element",{attrs:{underline:t.show==="lines"},scopedSlots:t._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:t._s(t.$gettext("Show"))}})]},proxy:!0},{key:"content",fn:function(){return[n("div",{directives:[{name:"gutter",rawName:"v-gutter",value:[0,2],expression:"[0, 2]"}]},[n("input-radio",{attrs:{value:"full"},on:{change:t.loadLog},model:{value:t.show,callback:function(m){t.show=m},expression:"show"}},[n("span",{domProps:{textContent:t._s(t.$gettext("Full Log"))}})]),t._v(" "),n("input-radio",{attrs:{value:"lines"},on:{change:t.loadLog},model:{value:t.show,callback:function(m){t.show=m},expression:"show"}},[n("span",{domProps:{textContent:t._s(t.$gettext("Tail"))}})])],1)]},proxy:!0}])}),t._v(" "),n("transition",{attrs:{name:"fade"}},[t.show==="lines"?n("ui-form-element",{attrs:{underline:!1},scopedSlots:t._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:t._s(t.$gettext("Number of lines to show"))}})]},proxy:!0},{key:"content",fn:function(){return[n("div",[n("input-text",{attrs:{number:""},on:{keyup:function(m){return!m.type.indexOf("key")&&t._k(m.keyCode,"enter",13,m.key,"Enter")?null:t.loadLog.apply(null,arguments)}},model:{value:t.lines,callback:function(m){t.lines=m},expression:"lines"}}),t._v(" "),n("ui-button",{attrs:{theme:"safe",size:"normal",disabled:!Number(t.lines)},on:{click:t.loadLog}},[n("span",{domProps:{textContent:t._s(t.$gettext("Reload Log"))}})])],1)]},proxy:!0}],null,!1,4012153659)}):t._e()],1)],1),t._v(" "),n("input-text-editor",{attrs:{value:t.log,"read-only":"","disable-modes":""},scopedSlots:t._u([{key:"header",fn:function(){return[n("div",{directives:[{name:"flex",rawName:"v-flex",value:{cross:"center",main:"between"},expression:`{
                            cross: 'center',
                            main: 'between',
                        }`}]},[t._v(`
                        `+t._s(t.domain)+`
                        `),n("ui-button-link",{attrs:{size:"small",theme:"light",href:t.rawLink,target:"_blank"}},[n("span",{domProps:{textContent:t._s(t.$gettext("raw"))}})])],1)]},proxy:!0}])})],1)]},proxy:!0}])})},i=[],r=s("./js/api/commands/user/stats.js"),g=s("./js/components/local/inputs/input-text-editor.vue"),f={components:{InputTextEditor:g.Z},preload:({domain:a,type:t})=>(0,r.Vb)({domain:a,type:t==="usage"?"log":"error",lines:"100"}),api:[{command:r.Vb,bind:"log"}],props:{domain:{type:String,required:!0},type:{type:String,required:!0}},data:()=>({lines:100,show:"lines"}),computed:{rawLink(){const a=this.type==="usage"?"log":"error",t=`/CMD_SHOW_LOG?domain=${this.domain}&type=${a}`;return this.show==="lines"?`${t}&lines=${this.lines}`:t},log(){return this.$api.log.join(`
`)},pageTitle(){const a=this.type==="usage"?this.$gettext("View Usage Log for %{ domain }"):this.$gettext("View Error Log for %{ domain }");return this.$gettextInterpolate(a,{domain:this.$domain})}},methods:{loadLog(){const a=this.type==="usage"?"log":"error";(0,r.Vb)({domain:this.domain,type:a,lines:this.show==="lines"?this.lines:null})}}},h=f,_=s("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/stats/log.vue?vue&type=style&index=0&id=3a436368&prod&lang=scss&scoped=true&"),u=s("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),c=(0,u.Z)(h,e,i,!1,null,"3a436368",null),p=c.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&":function(j,v,s){var e=s("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/inputs/input-text-editor.vue?vue&type=style&index=0&id=5dc63abc&prod&lang=scss&");e.__esModule&&(e=e.default),typeof e=="string"&&(e=[[j.id,e,""]]),e.locals&&(j.exports=e.locals);var i=s("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,r=i("bb557a88",e,!0,{})},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/stats/log.vue?vue&type=style&index=0&id=3a436368&prod&lang=scss&scoped=true&":function(j,v,s){var e=s("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/stats/log.vue?vue&type=style&index=0&id=3a436368&prod&lang=scss&scoped=true&");e.__esModule&&(e=e.default),typeof e=="string"&&(e=[[j.id,e,""]]),e.locals&&(j.exports=e.locals);var i=s("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,r=i("613a4fbc",e,!0,{})}}]);