import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
plt.rcParams.update({'font.family':'DejaVu Serif','font.size':9})
# ---- Fig 1 architecture ----
fig,ax=plt.subplots(figsize=(3.5,4.9),dpi=300); ax.set_xlim(0,100); ax.axis('off')
def box(x,y,w,h,title,sub,kind='solid',fill='white'):
    ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle='round,pad=0.4,rounding_size=2',lw=0.9,ec='#333' if kind!='major' else '#024950',fc=fill,ls='--' if kind=='support' else '-'))
    ax.text(x+w/2,y+h-3.2,title,ha='center',va='center',fontsize=7,weight='bold')
    ax.text(x+w/2,y+(h-6)/2+0.3,sub,ha='center',va='center',fontsize=5.5,color='#333',linespacing=1.15)
def arr(x1,y1,x2,y2,t=None,tx=None,ty=None):
    ax.annotate('',xy=(x2,y2),xytext=(x1,y1),arrowprops=dict(arrowstyle='-|>',lw=0.7,color='#333'))
    if t: ax.text(tx,ty,t,fontsize=5.5,color='#444',va='center')
H=15
box(1,128,31,H,'Live server','stdio / HTTP\ntools/list')
box(34.5,128,31,H,'Source files','.py .ts .js\n(read, not run)')
box(68,128,31,H,'Datasets','synthetic, MCPTox\nmanifests')
for x in (16.5,50,83.5): arr(x,127.4,50,118.6)
box(20,103,60,H,'Normaliser','NFKC; zero-width and look-alikes\nonly inside words; Base64 to text','support')
arr(50,102.4,50,93.6)
box(20,78,60,H,'Rule scanner','11 YAML rules + 3 obfuscation flags\nrisk score s in [0, 1]','support')
arr(50,77.4,50,68.6)
box(20,53,60,H,'Hybrid router','s <= 0.20 allow, s >= 0.50 block,\notherwise ask the judge','support')
box(64,28,35,H,'LLM-as-judge','untrusted <tool> text\nlabel + rationale','major',fill='#dbeef1')
arr(78,52.4,81.5,43.6,'uncertain',83,48.5)
box(1,28,35,H,'Fingerprint pin','tool hash per server\nCHANGED alert')
arr(50,52.4,50,18.6)
arr(64,35,57,18.6)
arr(18.5,27.4,40,18.6)
box(20,3,60,H,'Verdict per tool','allow / withhold, with the\nmatched words as the reason')
ax.add_patch(FancyBboxPatch((1,-6),4,3,boxstyle='square,pad=0',fc='#dbeef1',ec='#024950',lw=0.8)); ax.text(6.5,-4.5,'major technology (LLM)',fontsize=5.6,va='center')
ax.add_patch(FancyBboxPatch((50,-6),4,3,boxstyle='square,pad=0',fc='white',ec='#333',lw=0.8,ls='--')); ax.text(55.5,-4.5,'supporting static analysis',fontsize=5.6,va='center')
ax.set_ylim(-7,144)
plt.savefig('fig1.png',bbox_inches='tight',pad_inches=0.02)
# ---- Fig 2 normalisation effect ----
import numpy as np
fig,ax=plt.subplots(figsize=(3.5,1.9),dpi=300)
ds=['Synthetic\n(test, n=28)','MCPTox\n(27 unseen servers,\nn=1,060)','Real server files\n(n=28)']
off=[0.071,0.149,1/28]; on=[0.964,0.785,19/28]
lo_off=[0.020,0.129,0.006]; hi_off=[0.226,0.172,0.177]
x=np.arange(3); w=0.36
b1=ax.bar(x-w/2,off,w,color='#AFDDE5',ec='#024950',lw=0.6,label='rules, raw text')
b2=ax.bar(x+w/2,on,w,color='#024950',label='rules + normalisation')
for b,v in list(zip(b1,off))+list(zip(b2,on)): ax.text(b.get_x()+b.get_width()/2,v+0.03,f'{v:.2f}',ha='center',fontsize=6.5)
ax.set_xticks(x); ax.set_xticklabels(ds,fontsize=6.3); ax.set_ylim(0,1.12); ax.set_ylabel('recall, disguised attacks',fontsize=7)
ax.tick_params(axis='y',labelsize=6.5); ax.spines[['top','right']].set_visible(False)
ax.legend(fontsize=6.3,frameon=False,loc='upper right',ncol=2,bbox_to_anchor=(1,1.12))
plt.savefig('fig2.png',bbox_inches='tight',pad_inches=0.02)
