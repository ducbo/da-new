(self.webpackChunk=self.webpackChunk||[]).push([[6364],{"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/custombuild-header.vue?vue&type=style&index=0&id=0cc2af9f&prod&lang=scss&":function(){},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/sidebar-menu.vue?vue&type=style&index=0&id=4b77e098&prod&lang=scss&":function(){},"./js/pages/admin/custombuild/utils.ts":function(_,b,t){"use strict";t.d(b,{c:function(){return c}});var n=t("./js/composables/index.ts");const{$pgettext:f}=(0,n.st)(),c=(0,n.Lu)({BAD_REQUEST:f("custombuild","Bad Request: %{ message }")},f("custombuild","CustomBuild"))},"./js/pages/admin/custombuild/_components/custombuild-header.vue":function(_,b,t){"use strict";t.d(b,{Z:function(){return j}});var n=function(){var r=this,g=r._self._c,l=r._self._setupProxy;return g("div",{staticClass:"page-title"},[g("span",{staticClass:"title-text",domProps:{textContent:r._s(r.title)}}),r._v(" "),l.lastCommand?g("router-link",{staticClass:"command-running",class:{"--active":l.store.running},attrs:{to:{name:"admin/custombuild/plugin-logs/view",query:{log:l.log}}}},[g("span",{domProps:{textContent:r._s(l.store.running?r.$pgettext("custombuild","Active command:"):r.$pgettext("custombuild","Last command:"))}}),r._v(" "),g("span",{domProps:{textContent:r._s(`./build ${l.lastCommand}`)}})]):r._e()],1)},f=[],c=t("../node_modules/vue/dist/vue.common.prod.js"),y=t("./js/stores/index.ts"),S=(0,c.defineComponent)({__name:"custombuild-header",props:{title:null},setup(h){const r=(0,y.oR)(PiniaStores.CUSTOMBUILD),g=(0,c.computed)(()=>r.command.join(" ")),l=(0,c.computed)(()=>r.logfile);return{__sfc:!0,store:r,lastCommand:g,log:l}}}),R=S,C=t("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/custombuild-header.vue?vue&type=style&index=0&id=0cc2af9f&prod&lang=scss&"),$=t("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),x=(0,$.Z)(R,n,f,!1,null,null,null),j=x.exports},"./js/pages/admin/custombuild/_components/sidebar-menu.vue":function(_,b,t){"use strict";t.d(b,{Z:function(){return d}});var n=function(){var a=this,i=a._self._c,m=a._self._setupProxy;return i("div",[i("ui-infobar-item",{attrs:{id:"related-pages",title:a.$gettext("Related Pages")}},[i("ui-useful-links",{staticClass:"ui-useful-links",attrs:{links:m.relatedLinks},scopedSlots:a._u([{key:"links",fn:function(){return a._l(m.filteredVisibleLinks(m.relatedLinks),function(p){return i("ui-link",{key:p.key,staticClass:"ui-useful-links-entry menu-link",attrs:{name:p.name,tag:"div"}},[i("img",{directives:[{name:"margin",rawName:"v-margin:right",value:1,expression:"1",arg:"right"}],staticClass:"ui-useful-link-entry-icon",attrs:{src:p.icon,alt:p.label}}),a._v(" "),i("span",{domProps:{textContent:a._s(p.label)}})])})},proxy:!0}])})],1)],1)},f=[],c=t("../node_modules/vue/dist/vue.common.prod.js"),y=t("../node_modules/vue-router/composables.mjs"),S=t("../node_modules/ramda/es/index.js"),R=t.p+"assets/custombuild/update-software.64a121f7f10c38d2a437.svg",C=t.p+"assets/custombuild/build-software.c928770e488657597714.svg",$=t.p+"assets/custombuild/remove-software.90a1303af20d7697ad55.svg",x=t.p+"assets/custombuild/edit-options.e04d97cb74365d56205c.svg",j=t.p+"assets/custombuild/customize-versions.cfd18bbe1a079501ebcf.svg",h=t.p+"assets/custombuild/compilation-scripts.f735a8dc0099a55539a3.svg",r=t.p+"assets/custombuild/software-configuration.2fa783e26eda3df1b521.svg",g=t.p+"assets/custombuild/plugin-logs.0f9cd2cba96beca385e2.svg",l=t("./js/gettext.js"),P=(0,c.defineComponent)({__name:"sidebar-menu",setup(u){const a=(0,y.yj)(),i=[{label:(0,l.$pgettext)("custombuild","Updates Software"),name:"admin/custombuild/update-software",icon:R,key:"update-software"},{label:(0,l.$pgettext)("custombuild","Build Software"),name:"admin/custombuild/build-software",icon:C,key:"build-software"},{label:(0,l.$pgettext)("custombuild","Remove Software"),name:"admin/custombuild/remove-software",icon:$,key:"remove-software"},{label:(0,l.$pgettext)("custombuild","Edit Options"),name:"admin/custombuild/edit-options",icon:x,key:"edit-options"},{label:(0,l.$pgettext)("custombuild","Customize Versions"),name:"admin/custombuild/customize-versions",icon:j,key:"customize-versions"},{label:(0,l.$pgettext)("custombuild","Customize Compilation"),name:"admin/custombuild/customize-compilation",icon:h,key:"customize-compilation"},{label:(0,l.$pgettext)("custombuild","Actions"),name:"admin/custombuild/actions",icon:r,key:"actions"},{label:(0,l.$pgettext)("custombuild","Plugin Logs"),name:"admin/custombuild/plugin-logs",icon:g,key:"plugin-logs"}],m=v=>!a.fullPath.includes(v.key);return{__sfc:!0,route:a,relatedLinks:i,isNotCurrent:m,filteredVisibleLinks:v=>S.hXT(m,v)}}}),L=P,s=t("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/sidebar-menu.vue?vue&type=style&index=0&id=4b77e098&prod&lang=scss&"),e=t("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),o=(0,e.Z)(L,n,f,!1,null,null,null),d=o.exports},"./js/pages/admin/custombuild/remove-software.vue":function(_,b,t){"use strict";t.r(b),t.d(b,{default:function(){return L}});var n=function(){var e=this,o=e._self._c,d=e._self._setupProxy;return o("app-page",{staticClass:"custombuild-page",scopedSlots:e._u([{key:"page:title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$pgettext("custombuild","CustomBuild"))}})]},proxy:!0},{key:"default",fn:function(){return[o("custombuild-header",{attrs:{title:e.$pgettext("custombuild","Remove Software")}}),e._v(" "),o("app-page-section",{scopedSlots:e._u([{key:"footer:buttons",fn:function(){return[o("ui-button",{attrs:{theme:"danger",size:"big"},on:{click:function(u){return e.custombuild.runCommand(["remove_items"])}}},[e._v(`
                    `+e._s(e.$pgettext("custombuild","Remove all"))+`
                `)])]},proxy:!0},{key:"default",fn:function(){return[o("ui-table",{attrs:{items:e.removals}},[o("ui-column",{attrs:{id:"name",label:e.$pgettext("custombuild","Name"),fit:""}}),e._v(" "),o("ui-column",{attrs:{id:"description"}}),e._v(" "),o("ui-column",{attrs:{id:"remove-button",fit:""},scopedSlots:e._u([{key:"default",fn:function(u){return[o("ui-button",{attrs:{theme:"danger",size:"normal",disabled:e.custombuild.running},on:{click:function(a){return e.custombuild.runCommand(u.command)}}},[e._v(`
                                `+e._s(e.$pgettext("custombuild","Remove"))+`
                            `)])]}}])})],1)]},proxy:!0}])})]},proxy:!0},{key:"details",fn:function(){return[o("SidebarMenu")]},proxy:!0}])})},f=[],c=t("../node_modules/vue/dist/vue.common.prod.js"),y=t("./js/openapi/custombuild.ts"),S=t("./js/pages/admin/custombuild/utils.ts"),R=t("./js/pages/admin/custombuild/_components/custombuild-header.vue"),C=t("./js/stores/index.ts"),$=t("./js/pages/admin/custombuild/_components/sidebar-menu.vue");const x=(0,C.oR)(PiniaStores.CUSTOMBUILD),j=(0,c.ref)([]),h=async()=>{const{data:s,error:e}=await(0,y._4)();return e?((0,S.c)(e),!1):(j.value=s,!0)};var r=(0,c.defineComponent)({components:{CustombuildHeader:R.Z,SidebarMenu:$.Z},async beforeRouteEnter(s,e,o){if(!await h()){o(!1);return}o()},setup(){return(0,c.watch)(()=>x.running,s=>{s||h()}),{removals:j,custombuild:x}}}),g=r,l=t("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),P=(0,l.Z)(g,n,f,!1,null,null,null),L=P.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/custombuild-header.vue?vue&type=style&index=0&id=0cc2af9f&prod&lang=scss&":function(_,b,t){var n=t("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/custombuild-header.vue?vue&type=style&index=0&id=0cc2af9f&prod&lang=scss&");n.__esModule&&(n=n.default),typeof n=="string"&&(n=[[_.id,n,""]]),n.locals&&(_.exports=n.locals);var f=t("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,c=f("031cbf98",n,!0,{})},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/sidebar-menu.vue?vue&type=style&index=0&id=4b77e098&prod&lang=scss&":function(_,b,t){var n=t("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/sidebar-menu.vue?vue&type=style&index=0&id=4b77e098&prod&lang=scss&");n.__esModule&&(n=n.default),typeof n=="string"&&(n=[[_.id,n,""]]),n.locals&&(_.exports=n.locals);var f=t("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,c=f("95764150",n,!0,{})},"../node_modules/vue-router/composables.mjs":function(_,b,t){"use strict";t.d(b,{tv:function(){return c},yj:function(){return y}});var n=t("../node_modules/vue/dist/vue.common.prod.js");/*!
  * vue-router v3.6.5
  * (c) 2022 Evan You
  * @license MIT
  */function f(s){if(!getCurrentInstance())throw new Error("[vue-router]: Missing current instance. "+s+"() must be called inside <script setup> or setup().")}function c(){return(0,n.getCurrentInstance)().proxy.$root.$router}function y(){var s=(0,n.getCurrentInstance)().proxy.$root;if(!s._$route){var e=(0,n.effectScope)(!0).run(function(){return(0,n.shallowReactive)(Object.assign({},s.$router.currentRoute))});s._$route=e,s.$router.afterEach(function(o){Object.assign(e,o)})}return s._$route}function S(s){return j(s,R)}function R(s,e,o){var d=s.matched,u=e.matched;return d.length>=o&&d.slice(0,o+1).every(function(a,i){return a===u[i]})}function C(s,e,o){var d=s.matched,u=e.matched;return d.length<o||d[o]!==u[o]}function $(s){return j(s,C)}var x=function(){};function j(s,e){for(var o=getCurrentInstance(),d=c(),u=o.proxy;u&&u.$vnode&&u.$vnode.data&&u.$vnode.data.routerViewDepth==null;)u=u.$parent;var a=u&&u.$vnode&&u.$vnode.data?u.$vnode.data.routerViewDepth:null;if(a!=null){var i=d.beforeEach(function(m,p,v){return e(m,p,a)?s(m,p,v):v()});return onUnmounted(i),i}return x}function h(s){if(!(s.metaKey||s.altKey||s.ctrlKey||s.shiftKey)&&!s.defaultPrevented&&!(s.button!==void 0&&s.button!==0)){if(s.currentTarget&&s.currentTarget.getAttribute){var e=s.currentTarget.getAttribute("target");if(/\b_blank\b/i.test(e))return}return s.preventDefault&&s.preventDefault(),!0}}function r(s,e){var o=function(a){var i=e[a],m=s[a];if(typeof i=="string"){if(i!==m)return{v:!1}}else if(!Array.isArray(m)||m.length!==i.length||i.some(function(p,v){return p!==m[v]}))return{v:!1}};for(var d in e){var u=o(d);if(u)return u.v}return!0}function g(s,e){return Array.isArray(s)?l(s,e):Array.isArray(e)?l(e,s):s===e}function l(s,e){return Array.isArray(e)?s.length===e.length&&s.every(function(o,d){return o===e[d]}):s.length===1&&s[0]===e}function P(s,e){if(Object.keys(s).length!==Object.keys(e).length)return!1;for(var o in s)if(!g(s[o],e[o]))return!1;return!0}function L(s){var e=c(),o=y(),d=computed(function(){return e.resolve(unref(s.to),o)}),u=computed(function(){var p=d.value.route,v=p.matched,A=v.length,w=v[A-1],k=o.matched;if(!w||!k.length)return-1;var N=k.indexOf(w);if(N>-1)return N;var O=k[k.length-2];return A>1&&O&&O===w.parent}),a=computed(function(){return u.value>-1&&r(o.params,d.value.route.params)}),i=computed(function(){return u.value>-1&&u.value===o.matched.length-1&&P(o.params,d.value.route.params)}),m=function(p){var v=d.value.route;return h(p)?s.replace?e.replace(v):e.push(v):Promise.resolve()};return{href:computed(function(){return d.value.href}),route:computed(function(){return d.value.route}),isExactActive:i,isActive:a,navigate:m}}}}]);