(self.webpackChunk=self.webpackChunk||[]).push([[5659,8952],{"./js/api/commands/subdomains.js":function(v,d,e){"use strict";e.d(d,{AL:function(){return h},DG:function(){return o},HB:function(){return i},UZ:function(){return r},mz:function(){return c},xs:function(){return l}});var s=e("./js/api/command/index.js");const o=s.Z.get({id:"GET_SUBDOMAINS",url:"/CMD_SUBDOMAIN",schema:{domain:s.Z.DOMAIN,...s.Z.PAGINATION},after:n=>n.flow(n.moveProp("subdomains","rows"),n.moveProp("allow_subdomain_docroot_override","docroot"),n.processTableInfo("rows"),n.mapProps({awstats:m=>m!=="0",webalizer:n.isEqual("1"),docroot:n.isEqual("1"),has_php_selector:n.isEqual("yes"),rows:n.flow(n.toArray,n.mapArray(n.moveProp("subdomain_docroot_override","docroot")),n.mapArrayProps({bandwidth:n.convert.toAppNumber,stats:n.mapProps({webalizer_only:n.convert.toAppBoolean}),docroot:m=>{if(m&&Object.keys(m).length){if(typeof m.php1_select!="undefined"){const{options:x,value:f}=n.toSelect(m.php1_select);return{public_html:m.public_html,private_html:m.private_html,php_labels:x,php1_select:f}}return m}return!1}}))}))}),r=s.Z.post({url:"/CMD_SUBDOMAIN",params:{action:"create"},schema:{domain:s.Z.DOMAIN,subdomain:s.Z.REQUIRED_STRING,public_html:s.Z.OPTIONAL_STRING}}),i=s.Z.select({url:"/CMD_SUBDOMAIN",params:{action:"delete"},domain:!0,body:{contents:s.Z.REQUIRED_BOOL}}),l=s.Z.get({id:"GET_SUBDOMAIN_LOG",url:"/CMD_SHOW_LOG",params:{json:null},accept:"text/plain",schema:{domain:s.Z.DOMAIN,type:s.Z.REQUIRED_STRING,subdomain:s.Z.REQUIRED_STRING,lines:s.Z.OPTIONAL_STRING},after:n=>n.flow(n.convert.toLines,m=>m.slice(0,-1))}),c=s.Z.post({url:"/CMD_SUBDOMAIN",params:{action:"document_root_override"},domain:!0,schema:{subdomain:s.Z.REQUIRED_STRING,public_html:s.Z.OPTIONAL_STRING}}),h=s.Z.post({url:"/CMD_SUBDOMAIN",domain:!0,params:{action:"php_selector"},schema:{subdomain:s.Z.REQUIRED_STRING,php1_select:s.Z.REQUIRED_STRING}}),j=s.Z.get({url:"/CMD_SUBDOMAIN",id:"SUBDOMAIN_DATA",domain:!0,params:{action:"show_docroot_override"},schema:{subdomain:s.Z.REQUIRED_STRING},after:n=>n.flow(n.project({has_php_selector:"has_php_selector",http:"public_html",https:"private_html",php:"php1_select"}),n.mapProps({php:n.toSelect,has_php_selector:n.isEqual("yes")}))})},"./js/vue-globals/mixins.js":function(v,d,e){"use strict";e.r(d),e.d(d,{$bindTab:function(){return a},$clickOutside:function(){return $},$resizeListener:function(){return b},$scrollListener:function(){return D}});var s=e("../node_modules/vue/dist/vue.common.prod.js"),o=e.n(s),r=e("../node_modules/ramda/es/index.js"),i=e("./js/modules/file.js"),l=e("./js/modules/utils/index.js"),c=e("./js/modules/constants.js"),h=e("./js/modules/utils/css.js"),j=e("../node_modules/punycode/punycode.es6.js"),n=e("./js/vue-globals/helpers.js"),m=e("./js/stores/index.ts");const x=e("./js/vue-globals/mixins sync recursive \\.js$");(0,i.s)(x,t=>o().mixin(t.module)),o().mixin({data:()=>({isMounted:!1}),mounted(){this.isMounted=!0}}),o().mixin({methods:{$dialog(t){return{open:()=>n.uY.emit("dialog:open",t),close:()=>n.uY.emit("dialog:close",t)}}}}),o().mixin({computed:{$domain(){return this.$_ctx.session.domain},$domainUnicode(){return j.ZP.toUnicode(this.$domain)}}}),o().mixin({beforeCreate(){const t=(0,m.oR)(PiniaStores.VALIDATION);this.$valid=t.isValid.bind(t)}}),o().mixin({created(){this.regexps=c.gk}}),o().mixin({computed:{$p6e(){const t=u=>p=>{try{return u(p)}catch(g){return p}};return{toA:t(j.ZP.toASCII),toU:t(j.ZP.toUnicode),email2ascii:u=>{if(!u||!u.includes("@"))return u;const[p,g]=u.split("@");return[p,j.ZP.toASCII(g)].join("@")},email2unicode:u=>{if(!u||!u.includes("@"))return u;const[p,g]=u.split("@");return[p,j.ZP.toUnicode(g)].join("@")}}}}}),o().mixin({computed:{$_layout:(0,n.YM)("skin/layout")}}),o().mixin({methods:{$_useStore(t){return(0,m.oR)(t)}}});const f=[];document.body.addEventListener("click",t=>{f.forEach(u=>u(t.target))}),window.addEventListener("touchmove",t=>{f.forEach(u=>u(t.target))});const $={methods:{$clickOutsideListener(t,u){const p=E=>r.zGw(r.Bxt(u),r.qhW(Array.isArray,_=>[_]),r.hXT(r.CyQ(r.kKJ)),r.YPD(_=>_===E||_.contains(E)))(),g=E=>{p(E)&&this.$emit(`clickOutside:${t}`)};f.push(g)}}},D={methods:{__getScroller(){return this.$_layout==="sidebar"?window.document.querySelector("main"):window},__emitScroll(){this.$emit("window:scroll",window.pageYOffset)}},mounted(){const t=this.__getScroller();t&&t.addEventListener("scroll",this.__emitScroll)},destroyed(){const t=this.__getScroller();t&&t.removeEventListener("scroll",this.__emitScroll)}},O=[];window.addEventListener("resize",()=>{O.forEach(t=>t())});const b={created(){this.$resizeListener=()=>{this.$emit("window:resize",window.innerWidth)},O.push(this.$resizeListener)},destroyed(){O.splice(O.indexOf(this.$resizeListener),1)}},a=({param:t="tab",defaultTab:u}={param:"tab"})=>({computed:{[t]:{get(){return this.$route.params[t]||u},set(p){this.$route.params[t]!==p&&this.$router.replace(l._.merge({},this.$route,{params:{[t]:p}}))}}}})},"./js/vue-globals/mixins/bindApi.js":function(v,d,e){"use strict";e.r(d);var s=e("../node_modules/ramda/es/index.js");const o=(r,i)=>s.ETc(r.split("."),i);d.default={beforeCreate(){this.$options.commands&&(this.$commands=this.$options.commands)},computed:{$api(){if(!this.$options.api)return[];const r=this.$options.api;return typeof r=="function"?r.data.response:s.u4g((l,{command:c,bind:h})=>{if(typeof h=="string")return{...l,[h]:c.data.response};const j=s.u4g((n,[m,x])=>{const f=m.includes(".")?o(m,c.data):c.data[m]||c.data.response[m];return{...n,[x]:f}},{},s.Zpf(h));return{...l,...j}},{},r)}}}},"./js/vue-globals/mixins/local/clickOutside.js":function(v,d,e){"use strict";e.r(d),e.d(d,{$clickOutside:function(){return i}});var s=e("../node_modules/ramda/es/index.js");const o=[];document.body.addEventListener("click",l=>{o.forEach(s.gH4(l))}),window.addEventListener("touchstart",l=>{o.forEach(s.gH4(l))});const r=(l,c)=>s.zGw(s.qhW(Array.isArray,h=>[h]),s.hXT(s.CyQ(s.kKJ)),s.YPD(h=>h===l||h.contains(l)))(c),i={methods:{$clickOutsideListener(l,c){const h=j=>{r(j.target,c)&&this.$emit(`clickOutside:${l}`)};o.push(h)}}}},"./js/vue-globals/mixins/local/inputValidation.js":function(v,d,e){"use strict";e.r(d),e.d(d,{$inputValidation:function(){return r}});var s=e("./js/vue-globals/helpers.js"),o=e("./js/stores/index.ts");const r={inject:{groupID:{default:null},inputID:{default:null},validators:{default:()=>({})}},props:{id:{type:String,required:!1,default(){return this.inputID}},group:{type:String,required:!1,default(){return this.groupID}},novalidate:{type:Boolean,required:!1,default(){return!Object.keys(this.validators).length}}},computed:{validationStore(){return(0,o.oR)(PiniaStores.VALIDATION)},valid(){return this.validationStore.isValid(this.group,this.id)},errorState(){return!this.novalidate&&this.isUpdated&&!this.valid},isUpdated(){var i;const l=(i=this.validationStore.groups[this.group])==null?void 0:i[this.id];return typeof l=="undefined"?!1:l.updated}},methods:{$validate(i){this.id&&!this.novalidate&&this.validationStore.validate(this.groupID,this.id,i,this.validators)}},created(){if(!this.novalidate){const{validate:i}=this.$options;i&&this.$watch(i,(0,s.Ds)(this.$validate,{trailing:!0,leading:!1,delay:200}),{immediate:!0})}},destroyed(){this.novalidate||this.validationStore.deleteInput(this.group,this.id)}}},"./js/vue-globals/mixins/notification.js":function(v,d,e){"use strict";e.r(d);var s=e("./js/composables/index.ts");d.default={created(){const o=new s.d$;this.$notifications=o}}},"./js/vue-globals/mixins/reloadApiTable.js":function(v,d,e){"use strict";e.r(d);var s=e("./js/modules/constants.js");const o=i=>i.$options&&i.$options.name==="UiApiTable",r=i=>{const l=[i];let c=i;for(;c=l.shift();){if(o(c))return c;c.$children.length&&l.push(...c.$children)}return!1};d.default={methods:{$reloadApiTable({reset:i=!0}={}){const l=r(this);if(!l){s.Vi.DEV&&console.warn("$reloadApiTable called without any ui-api-table child");return}l.reloadTable(),i&&Object.assign(this.$data,this.$options.data.apply(this))}}}},"./js/vue-globals/mixins/session.js":function(v,d,e){"use strict";e.r(d);var s=e("./js/context/index.ts");d.default={computed:{$_ctx(){return s.T},$_flags(){return s.T.session.features},$_session(){return s.T.session.allValues}},methods:{$_cmd(o){return s.T.session.allowedCommands.includes(o)}}}},"./js/vue-globals/mixins/staticData.js":function(v,d,e){"use strict";e.r(d),d.default={created(){this.$options.staticData&&Object.entries(this.$options.staticData).forEach(([s,o])=>{this[s]=typeof o=="function"?o.bind(this)():o})}}},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/subdomains/stats.vue?vue&type=style&index=0&id=5a3e7d7c&prod&lang=scss&scoped=true&":function(){},"./js/pages/user/subdomains/stats.vue":function(v,d,e){"use strict";e.r(d),e.d(d,{default:function(){return O}});var s=function(){var a=this,t=a._self._c;return t("app-page",{attrs:{id:"subdomain-stats"}},[t("app-page-section",[t("ui-tabs",{attrs:{tabs:[a.webalizer?{id:"webalizer",label:a.$gettext("Webalizer")}:{},a.awstats?{id:"awstats",label:a.$gettext("AWstats")}:{}],"hide-single-tab":"",selected:a.tab},on:{"update:selected":function(u){a.tab=u}},scopedSlots:a._u([{key:"tab:webalizer",fn:function(){return[a.webalizer?t("iframe",{staticClass:"report",attrs:{src:a.webalizer,frameborder:"0"}}):t("app-page-section",{scopedSlots:a._u([{key:"section:title",fn:function(){return[t("span",{domProps:{textContent:a._s(a.$gettext("File does not exist"))}})]},proxy:!0}])},[a._v(" "),t("span",{domProps:{textContent:a._s(a.$gettext("You must wait for the stats to be computed. This will only happen *after* logs exist (domain must resolve and be used)."))}})])]},proxy:!0},{key:"tab:awstats",fn:function(){return[t("ui-form-element",{attrs:{vertical:a.clientStore.isPhone},scopedSlots:a._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:a._s(a.$gettext("Month"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-select",{attrs:{options:a.awstats},model:{value:a.report,callback:function(u){a.report=u},expression:"report"}})]},proxy:!0}])}),a._v(" "),a.report?t("iframe",{staticClass:"report",attrs:{src:a.report,frameborder:"0"}}):a._e()]},proxy:!0}])})],1)],1)},o=[],r=e("./js/stores/index.ts"),i=e("./js/api/commands/subdomains.js"),l=e("./js/api/command/index.js");const c=l.Z.get({id:"WEBALIZER_STATUS",url:"/CMD_FILE_MANAGER",response:!1,params:{action:"exists"},schema:{domain:l.Z.DOMAIN,subdomain:l.Z.OPTIONAL_STRING},before:({domain:b,subdomain:a})=>({path:a?`/domains/${b}/stats/${a}/index.html`:`/domains/${b}/stats/index.html`,domain:null,subdomain:null}),after:()=>({exists:b})=>b==="1"});var h=e("./js/vue-globals/mixins.js"),j=e("./js/modules/utils/index.js"),n=e("../node_modules/date-fns/esm/format/index.js"),m={preload:[i.DG,c],api:[{command:i.DG,bind:"subdomains"},{command:c,bind:"webalizerStatus"}],mixins:[(0,h.$bindTab)({param:"tab",defaultTab:"webalizer"})],props:{subdomain:{type:String,required:!0}},data:()=>({report:""}),computed:{awstats(){const b={January:this.$gettext("January"),February:this.$gettext("February"),March:this.$gettext("March"),April:this.$gettext("April"),May:this.$gettext("May"),June:this.$gettext("June"),July:this.$gettext("July"),August:this.$gettext("August"),September:this.$gettext("September"),October:this.$gettext("October"),November:this.$gettext("November"),December:this.$gettext("December")},a=new RegExp(Object.keys(b).join("|")),t=u=>(0,n.Z)(j.fp.convert.toAppDate(u),"MMMM yyyy",{awareOfUnicodeTokens:!0}).replace(a,p=>b[p]);if(this.$api.subdomains.awstats){const u=j.fp.transformObject((E,_)=>_==="has_dynamic"?{}:E==="present"?{[_]:this.$gettext("Present")}:{[_]:t(E)}),p=this.$api.subdomains.subdomain_awstats[this.subdomain];return{...p.has_dynamic==="1"?{[`/CMD_AWSTATS/${this.$domain}/${this.subdomain}/awstats.pl`]:this.$gettext("All Month(cgi)")}:{},...u(p)}}return!1},webalizer(){return this.$api.subdomains.webalizer&&this.$api.webalizerStatus?`/CMD_WEBALIZER/${this.$domain}/${this.subdomain}/index.html`:!1},...(0,r.Kc)(["client"])},created(){this.awstats&&([this.report]=Object.keys(this.awstats)),!this.webalizer&&this.awstats&&(this.tab="awstats")}},x=m,f=e("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/subdomains/stats.vue?vue&type=style&index=0&id=5a3e7d7c&prod&lang=scss&scoped=true&"),$=e("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),D=(0,$.Z)(x,s,o,!1,null,"5a3e7d7c",null),O=D.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/subdomains/stats.vue?vue&type=style&index=0&id=5a3e7d7c&prod&lang=scss&scoped=true&":function(v,d,e){var s=e("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/subdomains/stats.vue?vue&type=style&index=0&id=5a3e7d7c&prod&lang=scss&scoped=true&");s.__esModule&&(s=s.default),typeof s=="string"&&(s=[[v.id,s,""]]),s.locals&&(v.exports=s.locals);var o=e("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,r=o("6080b657",s,!0,{})},"./js/vue-globals/mixins sync recursive \\.js$":function(v,d,e){var s={"./bindApi.js":"./js/vue-globals/mixins/bindApi.js","./local/clickOutside.js":"./js/vue-globals/mixins/local/clickOutside.js","./local/inputValidation.js":"./js/vue-globals/mixins/local/inputValidation.js","./notification.js":"./js/vue-globals/mixins/notification.js","./reloadApiTable.js":"./js/vue-globals/mixins/reloadApiTable.js","./session.js":"./js/vue-globals/mixins/session.js","./staticData.js":"./js/vue-globals/mixins/staticData.js","vue-globals/mixins/bindApi.js":"./js/vue-globals/mixins/bindApi.js","vue-globals/mixins/local/clickOutside.js":"./js/vue-globals/mixins/local/clickOutside.js","vue-globals/mixins/local/inputValidation.js":"./js/vue-globals/mixins/local/inputValidation.js","vue-globals/mixins/notification.js":"./js/vue-globals/mixins/notification.js","vue-globals/mixins/reloadApiTable.js":"./js/vue-globals/mixins/reloadApiTable.js","vue-globals/mixins/session.js":"./js/vue-globals/mixins/session.js","vue-globals/mixins/staticData.js":"./js/vue-globals/mixins/staticData.js"};function o(i){var l=r(i);return e(l)}function r(i){if(!e.o(s,i)){var l=new Error("Cannot find module '"+i+"'");throw l.code="MODULE_NOT_FOUND",l}return s[i]}o.keys=function(){return Object.keys(s)},o.resolve=r,v.exports=o,o.id="./js/vue-globals/mixins sync recursive \\.js$"}}]);