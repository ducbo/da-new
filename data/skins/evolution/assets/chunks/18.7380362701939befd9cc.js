(self.webpackChunk=self.webpackChunk||[]).push([[18],{"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/global/ui/ui-page-menu.vue?vue&type=style&index=0&id=bcc5aeee&prod&lang=scss&":function(){},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/sidebar-menu.vue?vue&type=style&index=0&id=4b77e098&prod&lang=scss&":function(){},"./js/components/global/ui/ui-page-menu.vue":function(j,b,t){"use strict";t.r(b),t.d(b,{default:function(){return S}});var n=function(){var i=this,g=i._self._c,w=i._self._setupProxy;return g("div",{staticClass:"ui-page-menu"},[i._l(i.menu,function(s){return[g("div",{key:`header-${s.id}`,staticClass:"ui-page-menu-subheader",domProps:{textContent:i._s(s.label)}}),i._v(" "),g("div",{key:`entries-${s.id}`,staticClass:"ui-page-menu-group"},i._l(s.entries,function(c){return g("ui-link",{key:c.to,staticClass:"ui-page-menu-item",attrs:{tag:"div",name:c.to}},[g("span",{staticClass:"ui-page-menu-item-title"},[i._t("item-title",function(){return[i._v(`
                        `+i._s(c.label)+`
                    `)]},null,c)],2),i._v(" "),g("span",{staticClass:"ui-page-menu-item-subtitle"},[i._t("item-subtitle",function(){return[i._v(`
                        `+i._s(c.description)+`
                    `)]},null,c)],2)])}),1)]})],2)},_=[],f=t("../node_modules/vue/dist/vue.common.prod.js"),x=(0,f.defineComponent)({__name:"ui-page-menu",props:{menu:null},setup(h){return{__sfc:!0}}}),C=x,P=t("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/global/ui/ui-page-menu.vue?vue&type=style&index=0&id=bcc5aeee&prod&lang=scss&"),R=t("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),$=(0,R.Z)(C,n,_,!1,null,null,null),S=$.exports},"./js/pages/admin/custombuild/_components/sidebar-menu.vue":function(j,b,t){"use strict";t.d(b,{Z:function(){return d}});var n=function(){var a=this,r=a._self._c,m=a._self._setupProxy;return r("div",[r("ui-infobar-item",{attrs:{id:"related-pages",title:a.$gettext("Related Pages")}},[r("ui-useful-links",{staticClass:"ui-useful-links",attrs:{links:m.relatedLinks},scopedSlots:a._u([{key:"links",fn:function(){return a._l(m.filteredVisibleLinks(m.relatedLinks),function(p){return r("ui-link",{key:p.key,staticClass:"ui-useful-links-entry menu-link",attrs:{name:p.name,tag:"div"}},[r("img",{directives:[{name:"margin",rawName:"v-margin:right",value:1,expression:"1",arg:"right"}],staticClass:"ui-useful-link-entry-icon",attrs:{src:p.icon,alt:p.label}}),a._v(" "),r("span",{domProps:{textContent:a._s(p.label)}})])})},proxy:!0}])})],1)],1)},_=[],f=t("../node_modules/vue/dist/vue.common.prod.js"),x=t("../node_modules/vue-router/composables.mjs"),C=t("../node_modules/ramda/es/index.js"),P=t.p+"assets/custombuild/update-software.64a121f7f10c38d2a437.svg",R=t.p+"assets/custombuild/build-software.c928770e488657597714.svg",$=t.p+"assets/custombuild/remove-software.90a1303af20d7697ad55.svg",S=t.p+"assets/custombuild/edit-options.e04d97cb74365d56205c.svg",h=t.p+"assets/custombuild/customize-versions.cfd18bbe1a079501ebcf.svg",i=t.p+"assets/custombuild/compilation-scripts.f735a8dc0099a55539a3.svg",g=t.p+"assets/custombuild/software-configuration.2fa783e26eda3df1b521.svg",w=t.p+"assets/custombuild/plugin-logs.0f9cd2cba96beca385e2.svg",s=t("./js/gettext.js"),c=(0,f.defineComponent)({__name:"sidebar-menu",setup(l){const a=(0,x.yj)(),r=[{label:(0,s.$pgettext)("custombuild","Updates Software"),name:"admin/custombuild/update-software",icon:P,key:"update-software"},{label:(0,s.$pgettext)("custombuild","Build Software"),name:"admin/custombuild/build-software",icon:R,key:"build-software"},{label:(0,s.$pgettext)("custombuild","Remove Software"),name:"admin/custombuild/remove-software",icon:$,key:"remove-software"},{label:(0,s.$pgettext)("custombuild","Edit Options"),name:"admin/custombuild/edit-options",icon:S,key:"edit-options"},{label:(0,s.$pgettext)("custombuild","Customize Versions"),name:"admin/custombuild/customize-versions",icon:h,key:"customize-versions"},{label:(0,s.$pgettext)("custombuild","Customize Compilation"),name:"admin/custombuild/customize-compilation",icon:i,key:"customize-compilation"},{label:(0,s.$pgettext)("custombuild","Actions"),name:"admin/custombuild/actions",icon:g,key:"actions"},{label:(0,s.$pgettext)("custombuild","Plugin Logs"),name:"admin/custombuild/plugin-logs",icon:w,key:"plugin-logs"}],m=v=>!a.fullPath.includes(v.key);return{__sfc:!0,route:a,relatedLinks:r,isNotCurrent:m,filteredVisibleLinks:v=>C.hXT(m,v)}}}),y=c,e=t("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/sidebar-menu.vue?vue&type=style&index=0&id=4b77e098&prod&lang=scss&"),o=t("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),u=(0,o.Z)(y,n,_,!1,null,null,null),d=u.exports},"./js/pages/admin/custombuild/index.vue":function(j,b,t){"use strict";t.r(b),t.d(b,{default:function(){return g}});var n=function(){var s=this,c=s._self._c,y=s._self._setupProxy;return c("app-page",{scopedSlots:s._u([{key:"default",fn:function(){return[c("app-page-section",[c(y.UiPageMenu,{attrs:{menu:y.menu},scopedSlots:s._u([{key:"item-title",fn:function(e){return[c("ui-updates-bubble",{attrs:{label:e.label,content:e.to==="admin/custombuild/update-software"?y.store.updatesCount:0,float:!1}})]}}])})],1)]},proxy:!0},{key:"details",fn:function(){return[c(y.SidebarMenu)]},proxy:!0}])})},_=[],f=t("../node_modules/vue/dist/vue.common.prod.js"),x=t("./js/composables/index.ts"),C=t("./js/components/global/ui/ui-page-menu.vue"),P=t("./js/stores/index.ts"),R=t("./js/pages/admin/custombuild/_components/sidebar-menu.vue"),$=(0,f.defineComponent)({__name:"index",setup(w){const{$pgettext:s}=(0,x.st)(),c=(0,P.oR)(PiniaStores.CUSTOMBUILD),y=(0,f.computed)(()=>[{id:"software",label:s("custombuild","Software"),entries:[{to:"admin/custombuild/update-software",label:s("custombuild","Updates"),description:s("custombuild","Check and update existing software components.")},{to:"admin/custombuild/build-software",label:s("custombuild","Build"),description:s("custombuild","Install or rebuild new software components.")},{to:"admin/custombuild/remove-software",label:s("custombuild","Remove"),description:s("custombuild","Remove longer used software components.")}]},{id:"customize",label:s("custombuild","Settings"),entries:[{to:"admin/custombuild/edit-options",label:s("custombuild","Options"),description:s("custombuild","Edit CustomBuild options.conf and php_extentions.conf files.")},{to:"admin/custombuild/customize-versions",label:s("custombuild","Versions"),description:s("custombuild","Override latest software versions.")},{to:"admin/custombuild/customize-compilation",label:s("custombuild","Compilation"),description:s("custombuild","Override software compilation configuration.")}]},{id:"other",label:s("custombuild","Other"),entries:[{to:"admin/custombuild/actions",label:s("custombuild","Actions"),description:s("custombuild","Execute miscellaneous CustomBuild actions.")},{to:"admin/custombuild/plugin-logs",label:s("custombuild","Plugin logs"),description:s("custombuild","Check logs from the last CustomBuild executions.")}]}]);return{__sfc:!0,$pgettext:s,store:c,menu:y,UiPageMenu:C.default,SidebarMenu:R.Z}}}),S=$,h=t("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),i=(0,h.Z)(S,n,_,!1,null,null,null),g=i.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/global/ui/ui-page-menu.vue?vue&type=style&index=0&id=bcc5aeee&prod&lang=scss&":function(j,b,t){var n=t("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/global/ui/ui-page-menu.vue?vue&type=style&index=0&id=bcc5aeee&prod&lang=scss&");n.__esModule&&(n=n.default),typeof n=="string"&&(n=[[j.id,n,""]]),n.locals&&(j.exports=n.locals);var _=t("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,f=_("ea77a856",n,!0,{})},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/sidebar-menu.vue?vue&type=style&index=0&id=4b77e098&prod&lang=scss&":function(j,b,t){var n=t("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/custombuild/_components/sidebar-menu.vue?vue&type=style&index=0&id=4b77e098&prod&lang=scss&");n.__esModule&&(n=n.default),typeof n=="string"&&(n=[[j.id,n,""]]),n.locals&&(j.exports=n.locals);var _=t("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,f=_("95764150",n,!0,{})},"../node_modules/vue-router/composables.mjs":function(j,b,t){"use strict";t.d(b,{tv:function(){return f},yj:function(){return x}});var n=t("../node_modules/vue/dist/vue.common.prod.js");/*!
  * vue-router v3.6.5
  * (c) 2022 Evan You
  * @license MIT
  */function _(e){if(!getCurrentInstance())throw new Error("[vue-router]: Missing current instance. "+e+"() must be called inside <script setup> or setup().")}function f(){return(0,n.getCurrentInstance)().proxy.$root.$router}function x(){var e=(0,n.getCurrentInstance)().proxy.$root;if(!e._$route){var o=(0,n.effectScope)(!0).run(function(){return(0,n.shallowReactive)(Object.assign({},e.$router.currentRoute))});e._$route=o,e.$router.afterEach(function(u){Object.assign(o,u)})}return e._$route}function C(e){return h(e,P)}function P(e,o,u){var d=e.matched,l=o.matched;return d.length>=u&&d.slice(0,u+1).every(function(a,r){return a===l[r]})}function R(e,o,u){var d=e.matched,l=o.matched;return d.length<u||d[u]!==l[u]}function $(e){return h(e,R)}var S=function(){};function h(e,o){for(var u=getCurrentInstance(),d=f(),l=u.proxy;l&&l.$vnode&&l.$vnode.data&&l.$vnode.data.routerViewDepth==null;)l=l.$parent;var a=l&&l.$vnode&&l.$vnode.data?l.$vnode.data.routerViewDepth:null;if(a!=null){var r=d.beforeEach(function(m,p,v){return o(m,p,a)?e(m,p,v):v()});return onUnmounted(r),r}return S}function i(e){if(!(e.metaKey||e.altKey||e.ctrlKey||e.shiftKey)&&!e.defaultPrevented&&!(e.button!==void 0&&e.button!==0)){if(e.currentTarget&&e.currentTarget.getAttribute){var o=e.currentTarget.getAttribute("target");if(/\b_blank\b/i.test(o))return}return e.preventDefault&&e.preventDefault(),!0}}function g(e,o){var u=function(a){var r=o[a],m=e[a];if(typeof r=="string"){if(r!==m)return{v:!1}}else if(!Array.isArray(m)||m.length!==r.length||r.some(function(p,v){return p!==m[v]}))return{v:!1}};for(var d in o){var l=u(d);if(l)return l.v}return!0}function w(e,o){return Array.isArray(e)?s(e,o):Array.isArray(o)?s(o,e):e===o}function s(e,o){return Array.isArray(o)?e.length===o.length&&e.every(function(u,d){return u===o[d]}):e.length===1&&e[0]===o}function c(e,o){if(Object.keys(e).length!==Object.keys(o).length)return!1;for(var u in e)if(!w(e[u],o[u]))return!1;return!0}function y(e){var o=f(),u=x(),d=computed(function(){return o.resolve(unref(e.to),u)}),l=computed(function(){var p=d.value.route,v=p.matched,O=v.length,L=v[O-1],k=u.matched;if(!L||!k.length)return-1;var N=k.indexOf(L);if(N>-1)return N;var A=k[k.length-2];return O>1&&A&&A===L.parent}),a=computed(function(){return l.value>-1&&g(u.params,d.value.route.params)}),r=computed(function(){return l.value>-1&&l.value===u.matched.length-1&&c(u.params,d.value.route.params)}),m=function(p){var v=d.value.route;return i(p)?e.replace?o.replace(v):o.push(v):Promise.resolve()};return{href:computed(function(){return d.value.href}),route:computed(function(){return d.value.route}),isExactActive:r,isActive:a,navigate:m}}}}]);