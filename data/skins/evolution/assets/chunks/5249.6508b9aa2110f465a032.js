(self.webpackChunk=self.webpackChunk||[]).push([[5249],{"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/skin-options-controls.vue?vue&type=style&index=0&id=5e4530db&prod&lang=scss&":function(){},"./js/components/local/date-formats.vue":function(y,c,r){"use strict";r.d(c,{Z:function(){return h}});var u=function(){var t=this,n=t._self._c;return n("div",[n("ui-form-element",{scopedSlots:t._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:t._s(t.$gettext("Date Format"))}})]},proxy:!0},{key:"content",fn:function(){return[n("input-select",{attrs:{options:t.dateFormats,"disable-search":""},model:{value:t.date,callback:function(a){t.date=a},expression:"date"}})]},proxy:!0}])}),t._v(" "),t.date==="custom"?n("ui-form-element",{attrs:{group:"dateformats",validators:{required:!0,format:t.validateDatetime}},scopedSlots:t._u([{key:"title",fn:function(){return[n("div",{directives:[{name:"flex",rawName:"v-flex",value:{cross:"center"},expression:"{ cross: 'center' }"},{name:"padding",rawName:"v-padding:right",value:1,expression:"1",arg:"right"},{name:"flex-item",rawName:"v-flex-item",value:{grow:!0},expression:"{ grow: true }"}]},[n("div",{directives:[{name:"flex-item",rawName:"v-flex-item",value:{grow:!0},expression:"{ grow: true }"}]}),t._v(" "),n("ui-link",{attrs:{target:"_blank",href:"https://www.unicode.org/reports/tr35/tr35-dates.html#Date_Field_Symbol_Table",title:t.$gettext("Unicode Tokens")}},[n("ui-icon",{attrs:{id:"information",theme:"primary"}})],1)],1)]},proxy:!0},{key:"content",fn:function(){return[n("input-text",{attrs:{suffix:t.safeFormatNow(t.customDate)},model:{value:t.customDate,callback:function(a){t.customDate=a},expression:"customDate"}})]},proxy:!0},{key:"error:format",fn:function(){return[n("span",{domProps:{textContent:t._s(t.validation)}})]},proxy:!0}],null,!1,1805923388)}):t._e(),t._v(" "),n("ui-form-element",{attrs:{group:"dateformats",validators:{required:!0,format:t.validateDatetime}},scopedSlots:t._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:t._s(t.$gettext("Date & Time Format"))}})]},proxy:!0},{key:"content",fn:function(){return[t.date!=="custom"?n("input-text",{key:"computed",attrs:{novalidate:"",disabled:"",value:t.safeFormatNow(t.datetime)},scopedSlots:t._u([{key:"additions:right",fn:function(){return[n("input-checkbox-button",{attrs:{theme:"light",size:"normal"},model:{value:t.use24hFormat,callback:function(a){t.use24hFormat=a},expression:"use24hFormat"}},[n("span",{domProps:{textContent:t._s(t.$gettext("24H"))}})])]},proxy:!0}],null,!1,3728499649)}):n("input-text",{key:"customDatetime",attrs:{suffix:t.safeFormatNow(t.datetime)},model:{value:t.datetime,callback:function(a){t.datetime=a},expression:"datetime"}})]},proxy:!0},{key:"error:format",fn:function(){return[n("span",{domProps:{textContent:t._s(t.validation)}})]},proxy:!0}])}),t._v(" "),n("ui-form-element",{attrs:{underline:!1},scopedSlots:t._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:t._s(t.$gettext("Week Start"))}})]},proxy:!0},{key:"content",fn:function(){return[n("input-select",{attrs:{options:{monday:t.$gettext("Monday"),sunday:t.$gettext("Sunday")}},model:{value:t.start,callback:function(a){t.start=a},expression:"start"}})]},proxy:!0}])})],1)},p=[],l=r("../node_modules/date-fns/esm/format/index.js"),d=r("./js/modules/constants.js");const f=["yyyy-MM-dd","d-M-yyyy","M-d-yyyy","yyyy/M/d","d/M/yyyy","M/d/yyyy","d.M.yyyy"];var m={props:{dateFormat:{type:String,required:!0},datetimeFormat:{type:String,required:!0},weekStart:{type:String,required:!0}},data(){return{use24hFormat:this.datetimeFormat.includes("HH"),date:f.includes(this.dateFormat)?this.dateFormat:"custom",datetime:this.datetimeFormat,customDate:this.dateFormat,validation:"",start:this.weekStart}},computed:{dateFormats(){const s=this.reduceFormats(f);return s.custom=this.$gettext("Custom"),s}},watch:{datetimeFormat:{handler(s){this.datetime!==s&&(this.use24hFormat=s.includes("HH"),this.datetime=s)},immediate:!0},dateFormat(s){this.date!==s&&(this.date==="custom"?this.customDate=s:this.date=s)},datetime(s){s!==this.datetimeFormat&&this.checkFormat(s)&&this.$emit("update:datetimeFormat",s)},date(s){if(s!==this.dateFormat&&s!=="custom"){const t=this.use24hFormat?"HH:mm:ss":"pp";this.datetime=`${this.date} ${t}`,this.$emit("update:dateFormat",s)}},use24hFormat(s){this.datetime=this.datetime.replace(s?"pp":"HH:mm:ss",s?"HH:mm:ss":"pp")},customDate(s){s!==this.dateFormat&&this.$emit("update:dateFormat",s)},start(s){s!==this.weekStart&&this.$emit("update:weekStart",s)},weekStart(s){this.start!==s&&(this.start=s)}},methods:{safeFormatNow(s){return this.checkFormat(s)?(0,l.Z)(new Date,s,{awareOfUnicodeTokens:!0}):this.$gettext("Invalid date format")},reduceFormats(s){return s.reduce((t,n)=>({...t,[n]:this.safeFormatNow(n)}),{})},checkFormat(s){try{return(0,l.Z)(new Date,s,{awareOfUnicodeTokens:!0}),!0}catch(t){return this.validation=t.message,d.Vi.DEV&&console.error(t),!1}},validateDatetime(s){return s?this.checkFormat(s):!0}}},v=m,g=r("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),x=(0,g.Z)(v,u,p,!1,null,null,null),h=x.exports},"./js/components/local/skin-options-controls.vue":function(y,c,r){"use strict";r.d(c,{Z:function(){return n}});var u=function(){var e=this,o=e._self._c;return o("div",[o("app-page-section",{directives:[{name:"margin",rawName:"v-margin",value:2,expression:"2"}]},[e.showLayoutSelect?o("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Layout"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-select",{attrs:{options:{standard:e.$gettext("Standard"),sidebar:e.$gettext("Sidebar"),grid:e.$gettext("Icons Grid"),hybrid:e.$gettext("Hybrid"),standard2021:e.$gettext("Refreshed")}},model:{value:e.skinLayout,callback:function(i){e.skinLayout=i},expression:"skinLayout"}})]},proxy:!0}],null,!1,1590356643)}):e._e(),e._v(" "),o("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Dark Mode"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-select",{attrs:{options:{auto:e.$gettext("Auto"),enabled:e.$gettext("Enabled"),disabled:e.$gettext("Disabled")}},model:{value:e.darkMode,callback:function(i){e.darkMode=i},expression:"darkMode"}})]},proxy:!0}])}),e._v(" "),e.showLanguageSelect?o("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Language"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-select",e._b({staticClass:"fxi:grow:true",on:{change:e.setLanguage}},"input-select",{options:e.languages,selected:e.language},!1))]},proxy:!0}],null,!1,3039163249)}):e._e(),e._v(" "),o("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[o("span")]},proxy:!0},{key:"content",fn:function(){return[o("input-checkbox",{model:{value:e.disableRouteTransitions,callback:function(i){e.disableRouteTransitions=i},expression:"disableRouteTransitions"}},[o("span",{domProps:{textContent:e._s(e.$gettext("Disable Route Transitions"))}})])]},proxy:!0}])})],1),e._v(" "),o("app-page-section",{directives:[{name:"margin",rawName:"v-margin",value:[1,2],expression:"[1, 2]"}],scopedSlots:e._u([{key:"section:title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Date Formats"))}})]},proxy:!0}])},[e._v(" "),o("date-formats",{attrs:{"datetime-format":e.datetime,"date-format":e.date,"week-start":e.weekStart},on:{"update:datetimeFormat":function(i){e.datetime=i},"update:dateFormat":function(i){e.date=i},"update:weekStart":function(i){e.weekStart=i}}})],1),e._v(" "),o("app-page-section",{directives:[{name:"margin",rawName:"v-margin",value:[1,2],expression:"[1, 2]"}],scopedSlots:e._u([{key:"section:title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Tables"))}})]},proxy:!0}])},[e._v(" "),o("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Number of user domains shown"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-text",{attrs:{number:""},model:{value:e.userDomainLimit,callback:function(i){e.userDomainLimit=i},expression:"userDomainLimit"}})]},proxy:!0}])}),e._v(" "),o("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[o("span")]},proxy:!0},{key:"content",fn:function(){return[o("input-checkbox",{model:{value:e.highlightUsage,callback:function(i){e.highlightUsage=i},expression:"highlightUsage"}},[o("span",{domProps:{textContent:e._s(e.$gettext("Overusage highlight"))}})])]},proxy:!0}])}),e._v(" "),o("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[o("span",{domProps:{textContent:e._s(e.$gettext("Virtual Slice Size"))}})]},proxy:!0},{key:"content",fn:function(){return[o("input-text",{attrs:{number:""},model:{value:e.virtualSlice,callback:function(i){e.virtualSlice=i},expression:"virtualSlice"}})]},proxy:!0}])})],1)],1)},p=[],l=r("./js/stores/index.ts"),d=r("./js/vue-globals/helpers.js"),f=r("./js/components/local/date-formats.vue"),m=r("./js/modules/date-formats.ts"),v=r("./js/modules/dark-mode.ts"),g={components:{DateFormats:f.Z},computed:{highlightUsage:(0,d.YM)("tables/highlightUsage"),skinLayout:(0,d.YM)("skin/layout"),gridColorScheme:(0,d.YM)("grid-layout/color-scheme"),userDomainLimit:(0,d.YM)("tables/userDomainsLimit"),disableRouteTransitions:(0,d.YM)("skin/disable-route-transitions"),virtualSlice:(0,d.YM)("tables/virtual-slice"),dateFormats(){return m.f.value},datetime:{get(){return m.f.value.datetime},set(a){this.$_ctx.options.setItem("skin/date-formats/datetime",a)}},date:{get(){return m.f.value.date},set(a){this.$_ctx.options.setItem("skin/date-formats/date",a)}},weekStart:{get(){return m.f.value.weekStart},set(a){this.$_ctx.options.setItem("skin/date-formats/weekStart",a)}},language(){return(0,l.oR)(PiniaStores.LANG).current},languages(){return(0,l.oR)(PiniaStores.LANG).availableLanguages},showLayoutSelect(){const a=this.$_ctx.options["locked/force-layout-for-users"];return this.clientStore.isDesktop&&(this.$_useStore("user").hasRole("reseller")||a===!1)},showLanguageSelect(){return(0,l.oR)(PiniaStores.LANG).showSelector},darkMode:{set(a){v.ZR.value=a},get(){return v.ZR.value}},...(0,l.Kc)(["client"])},methods:{setLanguage(a){(0,l.oR)(PiniaStores.LANG).setLanguage(a)}}},x=g,h=r("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/skin-options-controls.vue?vue&type=style&index=0&id=5e4530db&prod&lang=scss&"),s=r("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),t=(0,s.Z)(x,u,p,!1,null,null,null),n=t.exports},"./js/pages/user/skin-options.vue":function(y,c,r){"use strict";r.r(c),r.d(c,{default:function(){return x}});var u=function(){var s=this,t=s._self._c;return t("app-page",{scopedSlots:s._u([{key:"default",fn:function(){return[t("controls")]},proxy:!0},{key:"footer:buttons",fn:function(){return[t("ui-button",{attrs:{theme:"danger",icon:"notifications-cancel"},on:{click:s.resetOptions}},[t("span",{domProps:{textContent:s._s(s.$gettext("Reset All"))}})])]},proxy:!0}])})},p=[],l=r("./js/components/local/skin-options-controls.vue"),d=r("./js/context/index.ts"),f={components:{Controls:l.Z},methods:{resetOptions(){d.T.options.clear()}}},m=f,v=r("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),g=(0,v.Z)(m,u,p,!1,null,null,null),x=g.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/skin-options-controls.vue?vue&type=style&index=0&id=5e4530db&prod&lang=scss&":function(y,c,r){var u=r("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/skin-options-controls.vue?vue&type=style&index=0&id=5e4530db&prod&lang=scss&");u.__esModule&&(u=u.default),typeof u=="string"&&(u=[[y.id,u,""]]),u.locals&&(y.exports=u.locals);var p=r("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,l=p("0e2821e8",u,!0,{})}}]);