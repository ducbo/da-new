(self.webpackChunk=self.webpackChunk||[]).push([[2743],{"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/custombuild-header.vue?vue&type=style&index=0&id=0cc2af9f&prod&lang=scss&":function(){},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/sidebar-menu.vue?vue&type=style&index=0&id=4b77e098&prod&lang=scss&":function(){},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/actions.vue?vue&type=style&index=0&id=c019c00a&prod&lang=scss&":function(){},"./js/pages/admin/custombuild/utils.ts":function(g,j,s){"use strict";s.d(j,{c:function(){return c}});var o=s("./js/composables/index.ts");const{$pgettext:p}=(0,o.st)(),c=(0,o.Lu)({BAD_REQUEST:p("custombuild","Bad Request: %{ message }")},p("custombuild","CustomBuild"))},"./js/pages/admin/custombuild/_components/custombuild-header.vue":function(g,j,s){"use strict";s.d(j,{Z:function(){return b}});var o=function(){var a=this,_=a._self._c,r=a._self._setupProxy;return _("div",{staticClass:"page-title"},[_("span",{staticClass:"title-text",domProps:{textContent:a._s(a.title)}}),a._v(" "),r.lastCommand?_("router-link",{staticClass:"command-running",class:{"--active":r.store.running},attrs:{to:{name:"admin/custombuild/plugin-logs/view",query:{log:r.log}}}},[_("span",{domProps:{textContent:a._s(r.store.running?a.$pgettext("custombuild","Active command:"):a.$pgettext("custombuild","Last command:"))}}),a._v(" "),_("span",{domProps:{textContent:a._s(`./build ${r.lastCommand}`)}})]):a._e()],1)},p=[],c=s("../node_modules/vue/dist/vue.common.prod.js"),y=s("./js/stores/index.ts"),h=(0,c.defineComponent)({__name:"custombuild-header",props:{title:null},setup(R){const a=(0,y.oR)(PiniaStores.CUSTOMBUILD),_=(0,c.computed)(()=>a.command.join(" ")),r=(0,c.computed)(()=>a.logfile);return{__sfc:!0,store:a,lastCommand:_,log:r}}}),S=h,C=s("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/custombuild-header.vue?vue&type=style&index=0&id=0cc2af9f&prod&lang=scss&"),P=s("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),x=(0,P.Z)(S,o,p,!1,null,null,null),b=x.exports},"./js/pages/admin/custombuild/_components/sidebar-menu.vue":function(g,j,s){"use strict";s.d(j,{Z:function(){return u}});var o=function(){var d=this,i=d._self._c,m=d._self._setupProxy;return i("div",[i("ui-infobar-item",{attrs:{id:"related-pages",title:d.$gettext("Related Pages")}},[i("ui-useful-links",{staticClass:"ui-useful-links",attrs:{links:m.relatedLinks},scopedSlots:d._u([{key:"links",fn:function(){return d._l(m.filteredVisibleLinks(m.relatedLinks),function(v){return i("ui-link",{key:v.key,staticClass:"ui-useful-links-entry menu-link",attrs:{name:v.name,tag:"div"}},[i("img",{directives:[{name:"margin",rawName:"v-margin:right",value:1,expression:"1",arg:"right"}],staticClass:"ui-useful-link-entry-icon",attrs:{src:v.icon,alt:v.label}}),d._v(" "),i("span",{domProps:{textContent:d._s(v.label)}})])})},proxy:!0}])})],1)],1)},p=[],c=s("../node_modules/vue/dist/vue.common.prod.js"),y=s("../node_modules/vue-router/composables.mjs"),h=s("../node_modules/ramda/es/index.js"),S=s.p+"assets/custombuild/update-software.64a121f7f10c38d2a437.svg",C=s.p+"assets/custombuild/build-software.c928770e488657597714.svg",P=s.p+"assets/custombuild/remove-software.90a1303af20d7697ad55.svg",x=s.p+"assets/custombuild/edit-options.e04d97cb74365d56205c.svg",b=s.p+"assets/custombuild/customize-versions.cfd18bbe1a079501ebcf.svg",R=s.p+"assets/custombuild/compilation-scripts.f735a8dc0099a55539a3.svg",a=s.p+"assets/custombuild/software-configuration.2fa783e26eda3df1b521.svg",_=s.p+"assets/custombuild/plugin-logs.0f9cd2cba96beca385e2.svg",r=s("./js/gettext.js"),$=(0,c.defineComponent)({__name:"sidebar-menu",setup(l){const d=(0,y.yj)(),i=[{label:(0,r.$pgettext)("custombuild","Updates Software"),name:"admin/custombuild/update-software",icon:S,key:"update-software"},{label:(0,r.$pgettext)("custombuild","Build Software"),name:"admin/custombuild/build-software",icon:C,key:"build-software"},{label:(0,r.$pgettext)("custombuild","Remove Software"),name:"admin/custombuild/remove-software",icon:P,key:"remove-software"},{label:(0,r.$pgettext)("custombuild","Edit Options"),name:"admin/custombuild/edit-options",icon:x,key:"edit-options"},{label:(0,r.$pgettext)("custombuild","Customize Versions"),name:"admin/custombuild/customize-versions",icon:b,key:"customize-versions"},{label:(0,r.$pgettext)("custombuild","Customize Compilation"),name:"admin/custombuild/customize-compilation",icon:R,key:"customize-compilation"},{label:(0,r.$pgettext)("custombuild","Actions"),name:"admin/custombuild/actions",icon:a,key:"actions"},{label:(0,r.$pgettext)("custombuild","Plugin Logs"),name:"admin/custombuild/plugin-logs",icon:_,key:"plugin-logs"}],m=f=>!d.fullPath.includes(f.key);return{__sfc:!0,route:d,relatedLinks:i,isNotCurrent:m,filteredVisibleLinks:f=>h.hXT(m,f)}}}),L=$,e=s("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/sidebar-menu.vue?vue&type=style&index=0&id=4b77e098&prod&lang=scss&"),n=s("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),t=(0,n.Z)(L,o,p,!1,null,null,null),u=t.exports},"./js/pages/admin/custombuild/actions.vue":function(g,j,s){"use strict";s.r(j),s.d(j,{default:function(){return e}});var o=function(){var t=this,u=t._self._c,l=t._self._setupProxy;return u("app-page",{staticClass:"custombuild-page",scopedSlots:t._u([{key:"page:title",fn:function(){return[u("span",{domProps:{textContent:t._s(t.$pgettext("custombuild","CustomBuild"))}})]},proxy:!0},{key:"default",fn:function(){return[u("CustombuildHeader",{attrs:{title:t.$pgettext("custombuild","Actions")}}),t._v(" "),u("app-page-section",[u("div",{staticClass:"build-target-grid"},t._l(t.actions,function(d){return u("div",{key:d.name,staticClass:"build-target-entry"},[u("div",{staticClass:"entry-header"},[u("span",{staticClass:"name",domProps:{textContent:t._s(d.name)}}),t._v(" "),u("span",{staticClass:"command",class:{"--disabled":t.custombuild.running},domProps:{textContent:t._s(`./build ${d.command.join(" ")}`)},on:{click:function(i){return t.custombuild.runCommand(d.command)}}})]),t._v(" "),u("span",{staticClass:"description",domProps:{textContent:t._s(d.description)}})])}),0)])]},proxy:!0},{key:"details",fn:function(){return[u("SidebarMenu")]},proxy:!0}])})},p=[],c=s("../node_modules/vue/dist/vue.common.prod.js"),y=s("./js/openapi/custombuild.ts"),h=s("./js/pages/admin/custombuild/utils.ts"),S=s("./js/pages/admin/custombuild/_components/custombuild-header.vue"),C=s("./js/stores/index.ts"),P=s("./js/pages/admin/custombuild/_components/sidebar-menu.vue");const x=(0,C.oR)(PiniaStores.CUSTOMBUILD),b=(0,c.ref)([]),R=async()=>{const{data:n,error:t}=await(0,y.Sv)();return t?((0,h.c)(t),!1):(b.value=n,!0)};var a=(0,c.defineComponent)({components:{CustombuildHeader:S.Z,SidebarMenu:P.Z},async beforeRouteEnter(n,t,u){if(!await R()){u(!1);return}u()},setup(){return(0,c.watch)(()=>x.running,n=>{n||R()}),{actions:b,custombuild:x}}}),_=a,r=s("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/actions.vue?vue&type=style&index=0&id=c019c00a&prod&lang=scss&"),$=s("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),L=(0,$.Z)(_,o,p,!1,null,null,null),e=L.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/custombuild-header.vue?vue&type=style&index=0&id=0cc2af9f&prod&lang=scss&":function(g,j,s){var o=s("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/custombuild-header.vue?vue&type=style&index=0&id=0cc2af9f&prod&lang=scss&");o.__esModule&&(o=o.default),typeof o=="string"&&(o=[[g.id,o,""]]),o.locals&&(g.exports=o.locals);var p=s("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,c=p("031cbf98",o,!0,{})},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/sidebar-menu.vue?vue&type=style&index=0&id=4b77e098&prod&lang=scss&":function(g,j,s){var o=s("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/sidebar-menu.vue?vue&type=style&index=0&id=4b77e098&prod&lang=scss&");o.__esModule&&(o=o.default),typeof o=="string"&&(o=[[g.id,o,""]]),o.locals&&(g.exports=o.locals);var p=s("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,c=p("95764150",o,!0,{})},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/actions.vue?vue&type=style&index=0&id=c019c00a&prod&lang=scss&":function(g,j,s){var o=s("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/actions.vue?vue&type=style&index=0&id=c019c00a&prod&lang=scss&");o.__esModule&&(o=o.default),typeof o=="string"&&(o=[[g.id,o,""]]),o.locals&&(g.exports=o.locals);var p=s("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,c=p("75c8ed28",o,!0,{})},"../node_modules/vue-router/composables.mjs":function(g,j,s){"use strict";s.d(j,{tv:function(){return c},yj:function(){return y}});var o=s("../node_modules/vue/dist/vue.common.prod.js");/*!
  * vue-router v3.6.5
  * (c) 2022 Evan You
  * @license MIT
  */function p(e){if(!getCurrentInstance())throw new Error("[vue-router]: Missing current instance. "+e+"() must be called inside <script setup> or setup().")}function c(){return(0,o.getCurrentInstance)().proxy.$root.$router}function y(){var e=(0,o.getCurrentInstance)().proxy.$root;if(!e._$route){var n=(0,o.effectScope)(!0).run(function(){return(0,o.shallowReactive)(Object.assign({},e.$router.currentRoute))});e._$route=n,e.$router.afterEach(function(t){Object.assign(n,t)})}return e._$route}function h(e){return b(e,S)}function S(e,n,t){var u=e.matched,l=n.matched;return u.length>=t&&u.slice(0,t+1).every(function(d,i){return d===l[i]})}function C(e,n,t){var u=e.matched,l=n.matched;return u.length<t||u[t]!==l[t]}function P(e){return b(e,C)}var x=function(){};function b(e,n){for(var t=getCurrentInstance(),u=c(),l=t.proxy;l&&l.$vnode&&l.$vnode.data&&l.$vnode.data.routerViewDepth==null;)l=l.$parent;var d=l&&l.$vnode&&l.$vnode.data?l.$vnode.data.routerViewDepth:null;if(d!=null){var i=u.beforeEach(function(m,v,f){return n(m,v,d)?e(m,v,f):f()});return onUnmounted(i),i}return x}function R(e){if(!(e.metaKey||e.altKey||e.ctrlKey||e.shiftKey)&&!e.defaultPrevented&&!(e.button!==void 0&&e.button!==0)){if(e.currentTarget&&e.currentTarget.getAttribute){var n=e.currentTarget.getAttribute("target");if(/\b_blank\b/i.test(n))return}return e.preventDefault&&e.preventDefault(),!0}}function a(e,n){var t=function(d){var i=n[d],m=e[d];if(typeof i=="string"){if(i!==m)return{v:!1}}else if(!Array.isArray(m)||m.length!==i.length||i.some(function(v,f){return v!==m[f]}))return{v:!1}};for(var u in n){var l=t(u);if(l)return l.v}return!0}function _(e,n){return Array.isArray(e)?r(e,n):Array.isArray(n)?r(n,e):e===n}function r(e,n){return Array.isArray(n)?e.length===n.length&&e.every(function(t,u){return t===n[u]}):e.length===1&&e[0]===n}function $(e,n){if(Object.keys(e).length!==Object.keys(n).length)return!1;for(var t in e)if(!_(e[t],n[t]))return!1;return!0}function L(e){var n=c(),t=y(),u=computed(function(){return n.resolve(unref(e.to),t)}),l=computed(function(){var v=u.value.route,f=v.matched,A=f.length,k=f[A-1],N=t.matched;if(!k||!N.length)return-1;var O=N.indexOf(k);if(O>-1)return O;var w=N[N.length-2];return A>1&&w&&w===k.parent}),d=computed(function(){return l.value>-1&&a(t.params,u.value.route.params)}),i=computed(function(){return l.value>-1&&l.value===t.matched.length-1&&$(t.params,u.value.route.params)}),m=function(v){var f=u.value.route;return R(v)?e.replace?n.replace(f):n.push(f):Promise.resolve()};return{href:computed(function(){return u.value.href}),route:computed(function(){return u.value.route}),isExactActive:i,isActive:d,navigate:m}}}}]);