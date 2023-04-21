"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[8499],{"./js/api/commands/bandwidth.js":function(v,m,r){var l=r("./js/api/command/index.js");m.Z=l.Z.get({id:"BANDWIDTH_BREAKDOWN",url:"/CMD_BANDWIDTH_BREAKDOWN",response:[],schema:{month:l.Z.OPTIONAL_STRING,year:l.Z.OPTIONAL_STRING,user:l.Z.OPTIONAL_STRING},before:n=>{const h=new Date,_=(h.getMonth()+1).toString(),f=h.getFullYear().toString();return typeof n.month=="undefined"||n.month===_&&n.year===f?{user:n.user,month:null,year:null}:n},after:n=>n.flow(n.wrap("rows"),n.moveProp("rows.total","total"),n.mapProp("rows",n.flow(n.deleteProps(["simpletotal","month","year"]),n.toArray,n.mapArray(n.mapValues(n.convert.toAppNumber)))),n.mapProp("total",n.mapValues(n.convert.toAppNumber)))})},"./js/components/local/history/base-charts.js":function(v,m,r){r.d(m,{o3:function(){return f},x1:function(){return p}});var l=r("../node_modules/chart.js/dist/chart.mjs");function n(u,d){return{render(c){return c("div",{style:this.styles,class:this.cssClasses},[c("canvas",{attrs:{id:this.chartId,width:this.width,height:this.height},ref:"canvas"})])},props:{chartId:{default:u,type:String},width:{default:400,type:Number},height:{default:400,type:Number},cssClasses:{type:String,default:""},styles:{type:Object},plugins:{type:Array,default(){return[]}}},data(){return{_chart:null}},created(){l.kL.register(...l.zX)},methods:{renderChart(c,y){this.$data._chart&&this.$data._chart.destroy();const b=y;if(this.plugins.length>0)for(const a of this.plugins)b.plugins={...b.plugins,...a};this.$data._chart=new l.kL(this.$refs.canvas.getContext("2d"),{type:d,data:c,options:b})}},beforeDestroy(){this.$data._chart&&this.$data._chart.destroy()}}}function h(u,d){if(d){let c=this.$data._chart,y=u.datasets.map(e=>e.label),b=d.datasets.map(e=>e.label);const a=JSON.stringify(b);JSON.stringify(y)===a&&d.datasets.length===u.datasets.length?(u.datasets.forEach((e,i)=>{const x=Object.keys(d.datasets[i]),O=Object.keys(e);x.filter(o=>o!=="_meta"&&O.indexOf(o)===-1).forEach(o=>{delete c.data.datasets[i][o]});for(const o in e)e.hasOwnProperty(o)&&(c.data.datasets[i][o]=e[o])}),u.hasOwnProperty("labels")&&(c.data.labels=u.labels,this.$emit("labels:update")),c.update(),this.$emit("chart:update")):(c&&(c.destroy(),this.$emit("chart:destroy")),this.renderChart(this.chartData,this.options),this.$emit("chart:render"))}else this.$data._chart&&(this.$data._chart.destroy(),this.$emit("chart:destroy")),this.renderChart(this.chartData,this.options),this.$emit("chart:render")}const _={data(){return{chartData:null}},watch:{chartData:h}},f={props:{chartData:{type:Object,required:!0,default:()=>{}}},watch:{chartData:h}},p=n("line-chart","line")},"./js/composables/dateFilter.ts":function(v,m,r){r.d(m,{W:function(){return f},f:function(){return h.f}});var l=r("../node_modules/ramda/es/index.js"),n=r("../node_modules/date-fns/esm/format/index.js"),h=r("./js/modules/date-formats.ts"),_=r("./js/modules/customizations/date-formats/default.ts");const f=l.WAo((p,u)=>{if(u)try{return(0,n.Z)(u,h.f.value[p])}catch(d){return console.warn(`Given ${p} format is incorrect:
${d.message}`),(0,n.Z)(u,_.d[p])}return""})},"./js/composables/filters.ts":function(v,m,r){r.d(m,{Q0:function(){return e},aS:function(){return x},d5:function(){return i},eB:function(){return b},hT:function(){return c},kC:function(){return d},n9:function(){return t},zM:function(){return y}});var l=r("../node_modules/date-fns/esm/formatDistance/index.js"),n=r("../node_modules/punycode/punycode.es6.js"),h=r("./js/composables/dateFilter.ts"),_=r("./js/composables/gettext.ts");const{$gettext:f,$ngettext:p,$gettextInterpolate:u}=(0,_.Z)(),d=s=>{var o;return s?((o=s.at(0))===null||o===void 0?void 0:o.toUpperCase())+s.slice(1):""},c=(s,o="datetime")=>(0,h.W)(o,s),y=s=>(0,l.Z)(s,new Date),b=(s,o=1024)=>{const g=Number(s);if(!g)return"0 B";const $=["B","KB","MB","GB","TB","PB","EB","ZB","YB"],D=Math.floor(Math.log(g)/Math.log(o));return`${parseFloat((g/o**D).toFixed(2))} ${$[D]}`},a=s=>{try{return(0,n.xX)(s)}catch(o){return s}},t=s=>(0,n.xX)(s),e=s=>{if(!s||!s.includes("@"))return s;const[o,g]=s.split("@");return[o,a(g)].join("@")},i=s=>{if(s<60)return f("less than a minute");const o=Math.floor(s/60)%60,g=Math.floor(s/3600)%24,$=Math.floor(s/(3600*24)),D=[$?p("%{days} day","%{days} days",$):null,g?p("%{hours} hour","%{hours} hours",g):null,o?p("%{minutes} minute","%{minutes} minutes",o):null].filter(Boolean).join(", ");return u(D,{days:$,hours:g,minutes:o})},x=(s,o)=>s.length<=o?s:`${s.substring(0,o)}...`,O=()=>({capitalize:d,date:c,distanceFromNow:y,humanReadableSize:b,p6eUnicode:t,p6eUnicodeEmail:e,formatUptime:i,truncateString:x})},"./js/components/local/line-chart.vue":function(v,m,r){r.d(m,{Z:function(){return d}});var l=r("./js/components/local/history/base-charts.js"),n={extends:l.x1,mixins:[l.o3],props:["chart","options"],mounted(){this.renderChart(this.chartData,this.options)}},h=n,_=r("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),f,p,u=(0,_.Z)(h,f,p,!1,null,null,null),d=u.exports},"./js/pages/user/bandwidth.vue":function(v,m,r){r.r(m),r.d(m,{default:function(){return b}});var l=function(){var t=this,e=t._self._c;return e("app-page",{scopedSlots:t._u([{key:"page:title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettextInterpolate(t.$gettext("Bandwidth Breakdown for %{month} %{year}"),{month:t.getMonthName(t.month),year:t.year}))}})]},proxy:!0},{key:"default",fn:function(){return[e("app-page-section",{directives:[{name:"flex",rawName:"v-flex",value:{main:"between"},expression:"{ main: 'between' }"}],staticClass:"filters"},[e("div",{directives:[{name:"gutter",rawName:"v-gutter",value:[1,null],expression:"[1, null]"}]},[e("div",{directives:[{name:"flex",rawName:"v-flex",value:{cross:"center"},expression:"{ cross: 'center' }"},{name:"gutter",rawName:"v-gutter",value:[null,1],expression:"[null, 1]"}]},[e("strong",{domProps:{textContent:t._s(t.$gettext("Show As:"))}}),t._v(" "),e("input-radio",{attrs:{value:"table"},model:{value:t.showAs,callback:function(i){t.showAs=i},expression:"showAs"}},[e("span",{domProps:{textContent:t._s(t.$gettext("Table"))}})]),t._v(" "),e("input-radio",{attrs:{value:"chart"},model:{value:t.showAs,callback:function(i){t.showAs=i},expression:"showAs"}},[e("span",{domProps:{textContent:t._s(t.$gettext("Chart"))}})])],1)])]),t._v(" "),e("transition",{attrs:{name:"fadeBounce"}},[t.showAs==="table"?e("app-page-section",[e("ui-r-table",t._b({scopedSlots:t._u([{key:"col:http",fn:function({http:i}){return[t._v(`
                        `+t._s(t.humanReadableSize(i))+`
                    `)]}},{key:"col:email",fn:function({email:i,email_count_incoming:x,email_count_outgoing:O}){return[t._v(`
                        `+t._s(t.humanReadableSize(i))+`
                        (`+t._s(x)+` /
                        `+t._s(O)+`)
                    `)]}},{key:"col:ftp",fn:function({ftp:i}){return[t._v(`
                        `+t._s(t.humanReadableSize(i))+`
                    `)]}},{key:"col:pop",fn:function({pop:i}){return[t._v(`
                        `+t._s(t.humanReadableSize(i))+`
                    `)]}},{key:"col:imap",fn:function({imap:i}){return[t._v(`
                        `+t._s(t.humanReadableSize(i))+`
                    `)]}},{key:"col:da",fn:function({da:i}){return[t._v(`
                        `+t._s(t.humanReadableSize(i))+`
                    `)]}},{key:"col:other",fn:function({other:i}){return[t._v(`
                        `+t._s(t.humanReadableSize(i))+`
                    `)]}},{key:"col:total",fn:function({total:i}){return[t._v(`
                        `+t._s(t.humanReadableSize(i))+`
                    `)]}},{key:"col:after:day",fn:function(){return[e("span",{staticClass:"txt:bold",domProps:{textContent:t._s(t.$gettext("Total"))}})]},proxy:!0},{key:"col:after:http",fn:function(){return[e("span",{staticClass:"txt:bold"},[t._v(`
                            `+t._s(t.humanReadableSize(t.total.http))+`
                        `)])]},proxy:!0},{key:"col:after:email",fn:function(){return[e("span",{staticClass:"txt:bold"},[t._v(`
                            `+t._s(t.humanReadableSize(t.total.email))+`
                            (`+t._s(t.total.email_count_incoming)+` /
                            `+t._s(t.total.email_count_outgoing)+`)
                        `)])]},proxy:!0},{key:"col:after:ftp",fn:function(){return[e("span",{staticClass:"txt:bold"},[t._v(`
                            `+t._s(t.humanReadableSize(t.total.ftp))+`
                        `)])]},proxy:!0},{key:"col:after:pop",fn:function(){return[e("span",{staticClass:"txt:bold"},[t._v(`
                            `+t._s(t.humanReadableSize(t.total.pop))+`
                        `)])]},proxy:!0},{key:"col:after:imap",fn:function(){return[e("span",{staticClass:"txt:bold"},[t._v(`
                            `+t._s(t.humanReadableSize(t.total.imap))+`
                        `)])]},proxy:!0},{key:"col:after:da",fn:function(){return[e("span",{staticClass:"txt:bold"},[t._v(`
                            `+t._s(t.humanReadableSize(t.total.da))+`
                        `)])]},proxy:!0},{key:"col:after:other",fn:function(){return[e("span",{staticClass:"txt:bold"},[t._v(`
                            `+t._s(t.humanReadableSize(t.total.other))+`
                        `)])]},proxy:!0},{key:"col:after:total",fn:function(){return[e("span",{staticClass:"txt:bold"},[t._v(`
                            `+t._s(t.humanReadableSize(t.total.total))+`
                        `)])]},proxy:!0}],null,!1,538565521)},"ui-r-table",{rows:t.entries,columns:t.columns,isCheckable:!1,isSortable:!0,disablePagination:!0,equalWidthLayout:!0,verticalLayout:t.clientStore.isPhone},!1))],1):e("app-page-section",[e("line-chart",t._b({},"line-chart",{chartData:t.chartData,options:t.chartOptions},!1))],1)],1)]},proxy:!0}])})},n=[],h=r("./js/stores/index.ts"),_=r("./js/api/commands/bandwidth.js"),f=r("./js/composables/filters.ts"),p=r("./js/components/local/line-chart.vue"),u={preload:_.Z,api:[{command:_.Z,bind:"breakdown"}],components:{LineChart:p.Z},props:{year:{type:String,required:!0},month:{type:String,required:!0}},data:()=>({showAs:"table"}),computed:{entries(){return this.$api.breakdown.rows},total(){return this.$api.breakdown.total},columns(){const a=[{id:"day",label:this.$gettext("Day"),editable:!1}];return a.push({id:"http",label:this.$gettext("Apache")}),a.push({id:"email",label:this.$gettext("E-mails (Incoming / Outgoing)")}),a.push({id:"ftp",label:this.$gettext("FTP")}),a.push({id:"pop",label:this.$gettext("POP")}),a.push({id:"imap",label:this.$gettext("IMAP")}),a.push({id:"da",label:this.$gettext("Direct Admin")}),a.push({id:"other",label:this.$gettext("Other")}),a.push({id:"total",label:this.$gettext("Total")}),a},chartData(){return{labels:this.entries.map(a=>a.day),datasets:[{label:this.$gettext("Total"),...this.datasetOptions("rgba(255, 99, 132, 1)"),...this.datasetData("total")},{label:this.$gettext("Apache"),...this.datasetOptions("rgba(1, 147, 202, 1)"),...this.datasetData("http")},{label:this.$gettext("E-mails"),...this.datasetOptions("rgba(228, 91, 0, 1)"),...this.datasetData("email")},{label:this.$gettext("FTP"),...this.datasetOptions("rgba(93, 195, 127, 1)"),...this.datasetData("ftp")},{label:this.$gettext("POP"),...this.datasetOptions("rgba(52, 56, 60, 1)"),...this.datasetData("pop")},{label:this.$gettext("IMAP"),...this.datasetOptions("rgba(0, 131, 180, 1)"),...this.datasetData("imap")},{label:this.$gettext("Direct Admin"),...this.datasetOptions("rgba(198, 208, 218, 1)"),...this.datasetData("da")},{label:this.$gettext("Other"),...this.datasetOptions("rgba(95, 111, 129, 1)"),...this.datasetData("Other")}]}},chartOptions(){return{scales:{y:{ticks:{callback:a=>this.getHumanReadableVolume(a)}}},plugins:{tooltip:{enabled:!0,mode:"nearest",intersect:!1,padding:10,titleFont:{family:"Open Sans"},bodyFont:{family:"Open Sans"},footerFont:{family:"Open Sans",size:10},displayColors:!1,callbacks:{title:a=>`${a[0].label} ${this.getMonthName(this.month)} ${this.year}`,label:({datasetIndex:a,raw:t})=>{const e=[this.$gettext("Total"),this.$gettext("Apache"),this.$gettext("E-mails"),this.$gettext("FTP"),this.$gettext("POP"),this.$gettext("IMAP"),this.$gettext("Direct Admin"),this.$gettext("Other")][a];return t!==0?`${e}: ${this.getHumanReadableVolume(t)}`:""}}}}}},...(0,h.Kc)(["client"])},methods:{humanReadableSize:f.eB,datasetOptions(a){return{backgroundColor:a.replace("1)","0.2)"),borderColor:a,pointBackgroundColor:a,borderWidth:2,pointRadius:2,pointHitRadius:20,fill:!1,tension:.4}},datasetData(a){return{data:this.entries.map(t=>t[a])}},getMonthName(a){return[this.$gettext("January"),this.$gettext("February"),this.$gettext("March"),this.$gettext("April"),this.$gettext("May"),this.$gettext("June"),this.$gettext("July"),this.$gettext("August"),this.$gettext("September"),this.$gettext("October"),this.$gettext("November"),this.$gettext("December")][parseInt(a,10)-1]},getHumanReadableVolume(a){return(0,f.eB)(a)}}},d=u,c=r("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),y=(0,c.Z)(d,l,n,!1,null,null,null),b=y.exports}}]);
