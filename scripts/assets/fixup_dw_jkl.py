import os
import struct
import sys
from pathlib import Path

sounds_inject = [
"walkmetaldry01.wav",
"walkmetaldry02.wav",
"runmetaldry01.wav",
"runmetaldry02.wav",
"kwalk01.wav",
"kwalk02.wav",
"kylerun01.wav",
"kylerun02.wav",
"fswtr2l.wav",
"fswtr2r.wav",
"walkdirt01.wav",
"walkdirt02.wav",
"rundirt01.wav",
"rundirt02.wav",
"splash1.wav",
"fsout1.wav",
"stroke1.wav",
"stroke2.wav",
"jumpbasic01.wav",
"jumpmetaldry01.wav",
"jumpdirt01.wav",
"landbasic01.wav",
"landmetaldry01.wav",
"landdirt01.wav",
"fswtr1l.wav",
"kylyld.wav",
"landhard01.wav",
"kyljpd.wav",
"kylgtsb.wav",
"kylgtsc.wav",
"kylgtlc.wav",
"kyljpa.wav",
"kylgtsa.wav",
"kylgtlb.wav",
"kylgtla.wav",
"i00ky86z.wav",
"i00ky71t.wav",
"kwaterdeath1.wav",
"kylgnb.wav",
"i00ky106.wav",
"bodyfall03.wav",
"ltsaberhit12.wav",
"ltsaberhit15.wav",
"df_door2-1.wav",
"df_door2-3.wav",
"df_door2-2.wav",
"df_elev1-1.wav",
"df_elev1-3.wav",
"df_elev1-2.wav",
"df_elev2-1.wav",
"df_elev2-3.wav",
"df_elev2-2.wav",
"punch03.wav",
"shothit02.wav",
"ricochet01.wav",
"kbodyhit01.wav",
"ricochet03.wav",
"expl_06.wav",
"ploop01.wav",
"thermal1.wav",
"shothit01.wav",
"ricochet02.wav",
"reptrrico01.wav",
"expl_07.wav",
"schargeplace01.wav",
"schargecountdown02.wav",
"railchargefly01.wav",
"railchargeattach.wav",
"expl_09.wav",
"punch02.wav",
"forcedestruct02.wav",
"ltsaberhit07.wav",
"ltsaberhit05.wav",
"ltsaberhit06.wav",
"ltsaberbodyhit01.wav",
"ltsaberhit01.wav",
"ltsaberhit02.wav",
"00rumbleamb01.wav",
"00conveyoramb02.wav",
"00exhaustamb04.wav",
"00techamb02.wav",
"00wind03.wav",
"01shipflyby01.wav",
"01shipflyby02.wav",
"01shipflyby03.wav",
"01shipflyby04.wav",
"activate02.wav",
"forcethrow01.wav",
"powerpu1.wav",
"activate01.wav",
"nrgpu1.wav",
"thrmlpu2.wav",
"bactapu1.wav",
"scalarm.wav",
"helthpu1.wav",
"crpickup01.wav",
"probeexplode01.wav",
"expl_04.wav",
"meddroidheal01.wav",
"mdroidshutoff01.wav",
"activate04.wav",
"forcefieldhit01.wav",
"set_hi2.wav",
"lgclick1.wav",
"turret-1.wav"
]

mat_inject = [
"hdback.mat 1.000000    1.000000",
"hdbottom.mat   1.000000    1.000000",
"hdftip.mat 1.000000    1.000000",
"hdsdthum.mat   1.000000    1.000000",
"hdinsid1.mat   1.000000    1.000000",
"hnd-wrt.mat    1.000000    1.000000",
"kyrarm.mat 1.000000    1.000000",
"hdgrip.mat 1.000000    1.000000",
"bryvgnbk.mat   1.000000    1.000000",
"bryvrsd.mat    1.000000    1.000000",
"bryvftp.mat    1.000000    1.000000",
"bryvfsd.mat    1.000000    1.000000",
"bryvgntp.mat   1.000000    1.000000",
"bryvgsgf.mat   1.000000    1.000000",
"bryvgsgt.mat   1.000000    1.000000",
"kysaber.mat    1.000000    1.000000",
"kyface3.mat    1.000000    1.000000",
"kyfaceb.mat    1.000000    1.000000",
"kyfacesd.mat   1.000000    1.000000",
"kyfacetp.mat   1.000000    1.000000",
"kyhand.mat 1.000000    1.000000",
"kyhandf.mat    1.000000    1.000000",
"kythigh.mat    1.000000    1.000000",
"kyfoot.mat 1.000000    1.000000",
"kyshotop.mat   1.000000    1.000000",
"kyneck.mat 1.000000    1.000000",
"kyshpad.mat    1.000000    1.000000",
"kyleg.mat  1.000000    1.000000",
"kybodyb.mat    1.000000    1.000000",
"kybodyf2.mat   1.000000    1.000000",
"kyforarm.mat   1.000000    1.000000",
"kysole.mat 1.000000    1.000000",
"kyhip.mat  1.000000    1.000000",
"kybutt.mat 1.000000    1.000000",
"rldvbrl2.mat   1.000000    1.000000",
"rldvbrl3.mat   1.000000    1.000000",
"rldvbrl1.mat   1.000000    1.000000",
"rldvsgt.mat    1.000000    1.000000",
"rldvbdtp.mat   1.000000    1.000000",
"rldvbdsd.mat   1.000000    1.000000",
"rldvbutt.mat   1.000000    1.000000",
"rldvclp2.mat   1.000000    1.000000",
"rldvchm2.mat   1.000000    1.000000",
"rldvchm3.mat   1.000000    1.000000",
"convclip.mat   1.000000    1.000000",
"convbrl2.mat   1.000000    1.000000",
"convbrl1.mat   1.000000    1.000000",
"convgril.mat   1.000000    1.000000",
"convbrl3.mat   1.000000    1.000000",
"convtop.mat    1.000000    1.000000",
"convbutt.mat   1.000000    1.000000",
"convclbk.mat   1.000000    1.000000",
"convbutp.mat   1.000000    1.000000",
"convgrip.mat   1.000000    1.000000",
"strvbrl4.mat   1.000000    1.000000",
"strvclp.mat    1.000000    1.000000",
"strvsid2.mat   1.000000    1.000000",
"strvtop2.mat   1.000000    1.000000",
"strvsid1.mat   1.000000    1.000000",
"strvsite.mat   1.000000    1.000000",
"strvsitb.mat   1.000000    1.000000",
"strvbutt.mat   1.000000    1.000000",
"d4x4.mat   1.000000    1.000000",
"rptpgril.mat   1.000000    1.000000",
"rptpside.mat   1.000000    1.000000",
"rptpbut2.mat   1.000000    1.000000",
"rptptop.mat    1.000000    1.000000",
"rptpundr.mat   1.000000    1.000000",
"brypgrip.mat   1.000000    1.000000",
"rptpbut1.mat   1.000000    1.000000",
"brypport.mat   1.000000    1.000000",
"rldvchm1.mat   1.000000    1.000000",
"pceltube.mat   1.000000    1.000000",
"pceltop.mat    1.000000    1.000000",
"pcelside.mat   1.000000    1.000000",
"ecelside.mat   1.000000    1.000000",
"ecelback.mat   1.000000    1.000000",
"ecelfrnt.mat   1.000000    1.000000",
"eceltop.mat    1.000000    1.000000",
"detpbelt.mat   1.000000    1.000000",
"det0side.mat   1.000000    1.000000",
"00wrat2y.mat   1.000000    1.000000",
"01wgraf4.mat   2.000000    1.600000",
"00twinkle.mat  1.000000    1.000000",
"gogfrnt.mat    1.000000    1.000000",
"gogside.mat    1.000000    1.000000",
"gogedge.mat    1.000000    1.000000",
"brypclbk.mat   1.000000    1.000000",
"brypclsd.mat   1.000000    1.000000",
"brypcltp.mat   1.000000    1.000000",
"strpport.mat   1.000000    1.000000",
"strpsitf.mat   1.000000    1.000000",
"strpgrip.mat   1.000000    1.000000",
"seqp1.mat  1.000000    1.000000",
"seqp2.mat  1.000000    1.000000",
"seqp3.mat  1.000000    1.000000",
"seqp4.mat  1.000000    1.000000",
"boost1.mat 1.000000    1.000000",
"boost2.mat 1.000000    1.000000",
"rldvprjs.mat   1.000000    1.000000",
"rldvprjf.mat   1.000000    1.000000",
"shld1.mat  1.000000    1.000000",
"shld2.mat  1.000000    1.000000",
"shld3.mat  1.000000    1.000000",
"e3x3top1.mat   1.000000    1.000000",
"cranbase.mat   1.000000    1.000000",
"tur1.mat   1.000000    1.000000",
"tur3.mat   1.000000    1.000000",
"tur2.mat   1.000000    1.000000",
"tur4.mat   1.000000    1.000000",
"conpside.mat   1.000000    1.000000",
"conptop.mat    1.000000    1.000000",
"conpfrnt.mat   1.000000    1.000000",
"conpclip.mat   1.000000    1.000000",
"bactbase.mat   1.000000    1.000000",
"bacttop1.mat   1.000000    1.000000",
"bactsde1.mat   1.000000    1.000000",
"bactsde2.mat   1.000000    1.000000",
"xtank1.mat 1.000000    1.000000",
"medskirt.mat   1.000000    1.000000",
"medhed2.mat    1.000000    1.000000",
"medhed3.mat    1.000000    1.000000",
"medab.mat  1.000000    1.000000",
"medleg.mat 1.000000    1.000000",
"medchst2.mat   1.000000    1.000000",
"medchst1.mat   1.000000    1.000000",
"medchst3.mat   1.000000    1.000000",
"medlimb1.mat   1.000000    1.000000",
"medlimb2.mat   1.000000    1.000000",
"crt6top2.mat   1.000000    1.000000",
"beamwd3.mat    1.000000    1.000000",
"dark.mat   1.000000    1.000000",
"lite.mat   1.000000    1.000000",
"00gsmoke.mat   1.000000    1.000000",
"dusty.mat  1.000000    1.000000",
"bry0side.mat   1.000000    1.000000",
"bry0top.mat    1.000000    1.000000",
"bryx.mat   1.000000    1.000000",
"str0side.mat   1.000000    1.000000",
"str0top.mat    1.000000    1.000000",
"det0metl.mat   1.000000    1.000000",
"detx.mat   1.000000    1.000000",
"00explosion.mat    1.000000    1.000000",
"bow0top.mat    1.000000    1.000000",
"bow0side.mat   1.000000    1.000000",
"bowx.mat   1.000000    1.000000",
"bry1top.mat    1.000000    1.000000",
"bow1side.mat   1.000000    1.000000",
"con0side.mat   1.000000    1.000000",
"rpt0top.mat    1.000000    1.000000",
"rptx.mat   1.000000    1.000000",
"sparky.mat 1.000000    1.000000",
"seq0side.mat   1.000000    1.000000",
"seq0top.mat    1.000000    1.000000",
"seq0mtp3.mat   1.000000    1.000000",
"seq0mbck.mat   1.000000    1.000000",
"seqx2.mat  1.000000    1.000000",
"debrisx.mat    1.000000    1.000000",
"shrp.mat   1.000000    1.000000",
"rld0clmp.mat   1.000000    1.000000",
"rldx.mat   1.000000    1.000000",
"conx.mat   1.000000    1.000000",
"con0top.mat    1.000000    1.000000",
"00ramp4.mat    1.000000    1.000000",
"ligt3.mat  1.000000    1.000000",
"sabvbld.mat    1.000000    1.000000",
"kysaber2.mat   1.000000    1.000000",
"kysaber1.mat   1.000000    1.000000",
"00teleport.mat 1.000000    1.000000",
"dstructparts.mat   1.000000    1.000000",
"destruct8.mat  1.000000    1.000000",
"forcedstruct.mat   1.000000    1.000000",
"00ramp1.mat    1.000000    1.000000",
"00ramp2.mat    1.000000    1.000000",
"bpck1.mat  1.000000    1.000000",
"bpck2.mat  1.000000    1.000000",
"bpck3.mat  1.000000    1.000000",
"bpck4.mat  1.000000    1.000000",
"brypblft.mat   1.000000    1.000000",
"brypblsd.mat   1.000000    1.000000",
"brypbltp.mat   1.000000    1.000000",
"brypprft.mat   1.000000    1.000000",
"brypside.mat   1.000000    1.000000",
"bowpside.mat   1.000000    1.000000",
"bowptop.mat    1.000000    1.000000",
"bowpgrip.mat   1.000000    1.000000",
"bowpscp1.mat   1.000000    1.000000",
"bowpscp2.mat   1.000000    1.000000",
"bowpbar1.mat   1.000000    1.000000",
"bowpprt1.mat   1.000000    1.000000",
"bowpbar2.mat   1.000000    1.000000",
"bowpprt2.mat   1.000000    1.000000",
"bowpball.mat   1.000000    1.000000",
"bowpstk1.mat   1.000000    1.000000",
"bowpstk2.mat   1.000000    1.000000",
"seqvmtp2.mat   1.000000    1.000000",
"dflt.mat   4.900000    3.900000",
"01wblk3d.mat   2.100000    2.200000",
"01WGRIL4.mat   2.100000    2.600000",
"01WGRIL1.mat   5.100000    3.400000",
"01wblkhd.mat   1.000000    1.000000",
"01wdock1.mat   1.000000    1.000000",
"00WPANL6.MAT   2.200000    11.100000",
"01whull2.mat   2.000000    3.100000",
"00wengn1.mat   1.500000    5.600000",
"01fstn.mat 1.000000    1.000000",
"01fmtl1.mat    3.100000    1.500000",
"01wblk2f.mat   2.000000    2.100000",
"01wcarg1.mat   2.400000    8.900001",
"01fbelt.mat    1.000000    1.000000",
"01wtest.mat    8.100000    1.700000",
"01WTECH2.mat   1.500000    5.100000",
"01WTECH3.mat   8.100000    2.100000",
"01wblk2d.mat   1.000000    1.000000",
"01WTECH1.mat   1.000000    1.000000",
"01wmtl1a.mat   2.900000    2.000000",
"01wexst6.mat   1.000000    1.000000",
"01wleb01.mat   1.000000    1.000000",
"01wlip1.mat    1.900000    2.100000",
"01w15.mat  1.000000    1.000000",
"01tabll1.mat   11.300000   2.800000",
"01w00.mat  1.600000    2.400000",
"01wbnk1b.mat   2.000000    2.000000",
"01whangr.mat   1.000000    1.000000",
"01wcrgo2.mat   1.500000    1.400000",
"01wblst1.mat   2.100000    2.900000",
"01wbolts.mat   1.500000    2.900000",
"01w16.mat  2.000000    1.500000",
"01wblk2.mat    2.100000    3.400000",
"01wbnk1a.mat   1.500000    1.400000",
"00t_6.mat  2.100000    2.100000",
"00wnew1.mat    1.000000    1.000000",
"00wbig3.MAT    1.000000    1.000000",
"00starry.mat   1.000000    1.000000",
"01wdock2.mat   1.000000    1.000000",
"00_YellowCued.mat  1.000000    1.000000",
"00t_4.mat  2.100000    1.300000",
"01f04.mat  1.800000    2.600000",
"01WTUBE2.mat   1.000000    1.000000",
"bubble.mat 1.000000    1.000000",
"splashx.mat    1.000000    1.000000",
"splooshx.mat   1.000000    1.000000"
]

model_inject = [
"bryv.3do",
"sabv.3do",
"ky.3do",
"rldv.3do",
"conv.3do",
"strv.3do",
"d4x4.3do",
"rptp.3do",
"rldp.3do",
"pcel.3do",
"ecel.3do",
"detp.3do",
"m2heat.3do",
"dark.3do",
"gogl.3do",
"strp.3do",
"seqp.3do",
"boost.3do",
"rcrg.3do",
"shld.3do",
"e3x3.3do",
"tur1.3do",
"conp.3do",
"bact.3do",
"xtank3a.3do",
"med.3do",
"crttoss1.3do",
"crttoss2.3do",
"mana1.3do",
"lite.3do",
"bry0.3do",
"str0.3do",
"det0.3do",
"bow0.3do",
"bow1.3do",
"rpt0.3do",
"seq0.3do",
"shrp_1.3do",
"shrp_2.3do",
"shrp_3.3do",
"shrp_4.3do",
"rld0.3do",
"con0.3do",
"ligt2.3do",
"sab0.3do",
"sabp.3do",
"bpck.3do",
"bryp.3do",
"detp_1.3do",
"bowp.3do",
"seqp_1.3do",
"shrp_5.3do"
]

sprite_inject = [
"bryx.spr",
"detx.spr",
"bowx2.spr",
"bowx.spr",
"rptx.spr",
"seqx2.spr",
"debrisx.spr",
"rldx.spr",
"conx.spr",
"destruct8.spr",
"forcedstruct_150.spr",
"twinkle.spr",
"bubble.spr",
"bubble2.spr",
"bubble3.spr",
"splash.spr",
"splooshx.spr",
"tiex.spr"
]

key_inject = [
"fistvmnt.key",
"fistvdis.key",
"fistvl.key",
"fistvr.key",
"bryvmnt.key",
"bryvpst1.key",
"bryvdis.key",
"strvmnt.key",
"strvdis.key",
"strvpst1.key",
"detvmnt.key",
"detvdis.key",
"detvpst1.key",
"detvpre1.key",
"bowvmnt.key",
"bowvdis.key",
"bowvpst1.key",
"rptvmnt.key",
"rptvdis.key",
"rptvpst1.key",
"rldvmnt.key",
"rldvdis.key",
"rldvpst1.key",
"seqvmnt.key",
"seqvdis.key",
"seqvpst1.key",
"convmnt.key",
"convdis.key",
"convpst1.key",
"sabvmnt.key",
"sabvdis.key",
"sabvsnp1.key",
"sabvrdy.key",
"sabvf1.key",
"sabvf2.key",
"sabvb1.key",
"sabvb2.key",
"sabvl1.key",
"sabvr1.key",
"sabvblk.key",
"sabvblk0.key",
"sabvblk1.key",
"sabvblk2.key",
"kystand0.key",
"kywalkf.key",
"kyrun0.key",
"kybackp0.key",
"kystrafl.key",
"kystrafr.key",
"kyftdeth.key",
"kyexdth0.key",
"kypnchl0.key",
"kypnchr0.key",
"kyhit0.key",
"kyjump.key",
"kydrop.key",
"kyfall.key",
"kyland.key",
"kyusew0.key",
"kycrchgn.key",
"kyrthro0.key",
"kyrthro1.key",
"kyusef0.key",
"kyltblt0.key",
"kydestr0.key",
"kygrip0.key",
"kychoke0.key",
"kyjumpf.key",
"kyturnr.key",
"kyturnl.key",
"kycrchbk.key",
"kyidle0.key",
"kyidle0b.key",
"kyhlstr.key",
"kydrawft.key",
"kydrawgn.key",
"kydrawsb.key",
"kystand2.key",
"kywalkg.key",
"kyrun2.key",
"kygndth0.key",
"kyfire.key",
"kyfirebg.key",
"kyidle2.key",
"kyidle2b.key",
"kystand1.key",
"kywalks.key",
"kyrun1.key",
"kybackp1.key",
"kyswdeth.key",
"kyidle1.key",
"kyidle1b.key",
"kysbtred.key",
"kysbswim.key",
"kysbback.key",
"kysbdeth.key",
"kysbpnch.key",
"kysbhit.key",
"kysbthr1.key",
"kysbthr2.key",
"kysbhlst.key",
"kysbdraw.key",
"kysbforc.key",
"kysbfire.key",
"kysbsabr.key",
"kyblock0.key",
"kyblock1.key",
"kyblock2.key",
"medheal.key",
"medidle.key",
"medoff.key"
]

pup_inject = [
"ky.pup",
"cr.pup",
"ra.pup"
]

snd_inject = [
"ky.snd",
"med_door.snd",
"sm_elev.snd",
"med_elev.snd",
"exp_punch.snd",
"exp_laserhit.snd",
"bry.snd",
"exp_fleshy.snd",
"stlaser.snd",
"exp_det.snd",
"det.snd",
"exp_bowhit.snd",
"bow.snd",
"exp_rpthit.snd",
"rep.snd",
"exp_med.snd",
"exp_small.snd",
"seq.snd",
"exp_raildet.snd",
"rail.snd",
"exp_conc.snd",
"conc.snd",
"exp_axe.snd",
"exp_dest.snd",
"exp_saber_wall.snd",
"exp_saber_blood.snd",
"exp_saber_saber.snd",
"exp_probe.snd",
"exp_tie.snd"
]

cog_inject = [
"kyle.cog",
"pow_repeater.cog",
"pow_railgun.cog",
"pow_power.cog",
"pow_energy.cog",
"pow_thermal.cog",
"pow_mana.cog",
"pow_goggles.cog",
"pow_strifle.cog",
"pow_sequencer.cog",
"pow_powerboost.cog",
"pow_railcharges.cog",
"pow_shields.cog",
"pow_concrifle.cog",
"pow_bacta.cog",
"xtank3.cog",
"00_twoonebee.cog",
"pow_darkside.cog",
"pow_lightside.cog",
"class_sequencer.cog",
"00_smoketrail.cog",
"pow_saber.cog",
"00_desttrail.cog",
"pow_backpack.cog",
"pow_bryar.cog",
"pow_single_thermal.cog",
"pow_crossbow.cog",
"pow_single_sequencer.cog",
"00_door.cog",
"M2_FFieldSwitch.cog",
"00_conveyor.cog",
"00_randomambient.cog",
"M2_dettrap.cog",
"00_elev_switch.cog",
"M2_turrettrap.cog"
]

template_inject = [
"_actor           none             orient=(0.000000/0.000000/0.000000) type=actor collide=1 move=physics thingflags=0x20000000 mass=150.000000 physflags=0x4a4f maxrotvel=200.000000 maxvel=1.000000 health=40.00 maxhealth=40.00 maxrotthrust=180.00 jumpspeed=1.50 eyeoffset=(0.000000/0.000000/0.037000) minheadpitch=-80.00 maxheadpitch=80.00 lightoffset=(0.000000/0.070000/0.040000) lightintensity=0.80 ",
"walkplayer       _actor           type=player thingflags=0x20000401 light=0.200000 model3d=ky.3do size=0.065000 movesize=0.065000 puppet=ky.pup soundclass=ky.snd cog=kyle.cog surfdrag=3.000000 airdrag=0.500000 staticdrag=0.300000 health=100.00 maxhealth=100.00 maxthrust=2.00 typeflags=0x1 error=0.50 fov=0.71 chance=1.00 ",
"_decor           none             orient=(0.000000/0.000000/0.000000) type=cog collide=1 move=path ",
"_structure       _decor           collide=3 thingflags=0x8 ",
"_walkstruct      _structure       thingflags=0x400048 ",
"4x4door          _walkstruct      model3d=d4x4.3do size=0.320400 movesize=0.320400 soundclass=med_door.snd ",
"_powerup         none             orient=(0.000000/0.000000/0.000000) type=item collide=1 move=physics size=0.100000 movesize=0.010000 surfdrag=3.000000 airdrag=1.000000 mass=10.000000 height=0.050000 physflags=0x400000 angvel=(0.000000/90.000000/0.000000) typeflags=0x1 respawn=30.000000 ",
"repeatergun      _powerup         thingflags=0x400 model3d=rptp.3do cog=pow_repeater.cog ",
"railgun          _powerup         thingflags=0x400 model3d=rldp.3do cog=pow_railgun.cog respawn=60.000000 ",
"powercell        _powerup         thingflags=0x400 model3d=pcel.3do cog=pow_power.cog ",
"energycell       _powerup         thingflags=0x400 model3d=ecel.3do cog=pow_energy.cog ",
"detonator        _powerup         thingflags=0x400 model3d=detp.3do cog=pow_thermal.cog ",
"m2heater         _walkstruct      thingflags=0x4c model3d=m2heat.3do size=0.324037 movesize=0.324037 ",
"manaboost        _powerup         thingflags=0x400 model3d=dark.3do cog=pow_mana.cog ",
"goggles          _powerup         thingflags=0x400 model3d=gogl.3do cog=pow_goggles.cog respawn=60.000000 ",
"strifle          _powerup         thingflags=0x400 model3d=strp.3do cog=pow_strifle.cog ",
"seqcharge        _powerup         thingflags=0x400 model3d=seqp.3do cog=pow_sequencer.cog ",
"powerboost       _powerup         thingflags=0x400 model3d=boost.3do cog=pow_powerboost.cog respawn=60.000000 ",
"railcharges      _powerup         thingflags=0x400 model3d=rcrg.3do cog=pow_railcharges.cog ",
"shieldrecharge   _powerup         thingflags=0x400 model3d=shld.3do cog=pow_shields.cog ",
"ghost            none             orient=(0.000000/0.000000/0.000000) type=ghost move=path ",
"3x3elev          _walkstruct      model3d=e3x3.3do size=0.209751 movesize=0.209751 soundclass=sm_elev.snd ",
"_zwalkstruct     _structure       thingflags=0x400040 ",
"m2boxturret      _zwalkstruct     model3d=tur1.3do size=0.139457 movesize=0.139457 soundclass=med_elev.snd ",
"concrifle        _powerup         thingflags=0x400 model3d=conp.3do cog=pow_concrifle.cog respawn=60.000000 ",
"bactatank        _powerup         thingflags=0x400 model3d=bact.3do cog=pow_bacta.cog respawn=60.000000 ",
"xtank3a          _walkstruct      thingflags=0x400448 model3d=xtank3a.3do size=0.191956 movesize=0.191956 cog=xtank3.cog ",
"twoonebee        none             orient=(0.000000/0.000000/0.000000) type=cog collide=1 thingflags=0x400 model3d=med.3do size=0.060000 movesize=0.060000 puppet=cr.pup cog=00_twoonebee.cog ",
"_throwable       none             orient=(0.000000/0.000000/0.000000) type=debris collide=1 move=physics movesize=0.010000 surfdrag=3.000000 airdrag=1.000000 mass=25.000000 height=0.011000 physflags=0x404041 buoyancy=0.500000 ",
"throwcrate1      _throwable       model3d=crttoss1.3do size=0.036400 movesize=0.036400 height=0.036500 ",
"throwcrate2      _throwable       model3d=crttoss2.3do size=0.036400 movesize=0.036400 height=0.036500 ",
"darkside         _powerup         thingflags=0x400 model3d=mana1.3do cog=pow_darkside.cog respawn=60.000000 ",
"lightside        _powerup         thingflags=0x400 model3d=lite.3do cog=pow_lightside.cog respawn=60.000000 ",
"_weapon          none             orient=(0.000000/0.000000/0.000000) type=weapon collide=1 move=physics thingflags=0x20000000 timer=10.000000 mass=5.000000 physflags=0x200 maxrotvel=90.000000 damageclass=0x2 typeflags=0x1 ",
"_explosion       none             orient=(0.000000/0.000000/0.000000) type=explosion typeflags=0x1 damageclass=0x4 ",
"+whitecloud      none             orient=(0.000000/0.000000/0.000000) type=particle timer=0.200000 typeflags=0x3f material=00gsmoke.mat range=0.020000 rate=128.000000 maxthrust=30.000000 elementsize=0.007000 count=128 ",
"+dustcloud       +whitecloud      timer=0.120000 material=dusty.mat range=0.015000 rate=256.000000 maxthrust=80.000000 elementsize=0.010000 ",
"+punchcloud      +dustcloud       timer=0.150000 material=00gsmoke.mat range=0.006000 rate=64.000000 maxthrust=4.000000 elementsize=0.004000 count=16 ",
"+punch_exp       _explosion       timer=0.001000 soundclass=exp_punch.snd creatething=+punchcloud typeflags=0x0 ",
"+punch           _weapon          size=0.001000 movesize=0.001000 mass=50.000000 explode=+punch_exp fleshhit=+punch_exp damage=20.000000 damageclass=0x1 typeflags=0x200d range=0.150000 force=50.000000 ",
"+laserhit        _explosion       thingflags=0x1 light=0.200000 timer=0.500000 sprite=bryx.spr soundclass=exp_laserhit.snd typeflags=0x33 blasttime=0.300000 maxlight=0.400000 ",
"+smflash         _explosion       thingflags=0x1 light=0.400000 timer=0.100000 typeflags=0x0 ",
"+laserfleshhit   +laserhit        soundclass=exp_fleshy.snd ",
"+bryarbolt       _weapon          thingflags=0x20000001 light=0.400000 model3d=bry0.3do size=0.001000 movesize=0.001000 soundclass=bry.snd creatething=+smflash maxrotvel=0.000000 vel=(0.000000/4.000000/0.000000) explode=+laserhit fleshhit=+laserfleshhit damage=30.000000 mindamage=10.000000 typeflags=0x20440d rate=15.000000 ",
"+stlaser         +bryarbolt       model3d=str0.3do soundclass=stlaser.snd vel=(0.000000/6.000000/0.000000) rate=10.000000 ",
"+firecloud       +dustcloud       material=00explosion.mat range=0.050000 rate=64.000000 maxthrust=40.000000 count=64 ",
"+grenade_exp     _explosion       thingflags=0x1 light=0.200000 timer=0.800000 sprite=detx.spr soundclass=exp_det.snd creatething=+firecloud typeflags=0x17 damage=75.000000 blasttime=0.700000 force=100.000000 maxlight=0.800000 range=0.450000 ",
"+grenade2        _weapon          timer=3.000000 model3d=det0.3do size=0.014895 movesize=0.014895 soundclass=det.snd surfdrag=3.000000 airdrag=0.800000 mass=1.000000 physflags=0x225 vel=(0.000000/2.000000/1.500000) angvel=(90.000000/45.000000/90.000000) buoyancy=0.250000 explode=+grenade_exp fleshhit=+grenade_exp damageclass=0x4 typeflags=0x40309 ",
"+grenade1        +grenade2        timer=10.000000 typeflags=0x4030d ",
"+crossbowhit     +laserhit        sprite=bowx2.spr soundclass=exp_bowhit.snd ",
"+lgflash         _explosion       thingflags=0x1 light=0.300000 timer=0.400000 typeflags=0x12 blasttime=0.200000 maxlight=1.000000 ",
"+crossbowbolt    _weapon          thingflags=0x20000001 light=0.500000 model3d=bow0.3do size=0.005000 movesize=0.005000 soundclass=bow.snd creatething=+lgflash vel=(0.000000/5.000000/0.000000) angvel=(0.000000/0.000000/120.000000) explode=+crossbowhit fleshhit=+crossbowhit damage=60.000000 mindamage=20.000000 damageclass=0x4 typeflags=0x20440d rate=10.000000 ",
"+crossbowhit2    _explosion       thingflags=0x1 light=0.200000 timer=0.500000 sprite=bowx.spr typeflags=0x33 blasttime=0.300000 maxlight=0.400000 ",
"+crossbowbolt2   +crossbowbolt    model3d=bow1.3do soundclass=none creatething=none explode=+crossbowhit2 fleshhit=+crossbowhit2 damage=40.000000 typeflags=0x440d ",
"+crossbowbolt3   +crossbowbolt    typeflags=0x28440d ",
"+repeaterhit     +laserhit        sprite=rptx.spr soundclass=exp_rpthit.snd ",
"+rpt_sparks      none             orient=(0.000000/0.000000/0.000000) type=particle move=physics timer=0.700000 mass=0.100000 physflags=0x400201 vel=(0.000000/0.000000/0.200000) typeflags=0x27 material=sparky.mat range=0.040000 rate=24.000000 maxthrust=7.000000 elementsize=0.005000 count=24 ",
"+rptfleshhit     _explosion       thingflags=0x1 light=0.100000 timer=0.800000 soundclass=exp_fleshy.snd creatething=+rpt_sparks typeflags=0x12 blasttime=0.700000 maxlight=0.300000 ",
"+repeaterball    _weapon          thingflags=0x20000001 light=0.300000 model3d=rpt0.3do size=0.005000 movesize=0.005000 soundclass=rep.snd creatething=+smflash vel=(0.000000/6.000000/0.000000) explode=+repeaterhit fleshhit=+rptfleshhit damage=20.000000 mindamage=5.000000 typeflags=0x440d rate=20.000000 ",
"+firecloud2      +firecloud       elementsize=0.012500 ",
"+firecloud3      +firecloud       maxthrust=20.000000 count=32 ",
"+debris_exp      _explosion       timer=1.000000 sprite=debrisx.spr soundclass=exp_small.snd creatething=+firecloud3 typeflags=0x7 blasttime=0.500000 ",
"_debris          none             orient=(0.000000/0.000000/0.000000) type=weapon collide=1 move=physics timer=1.100000 airdrag=3.000000 physflags=0x201 vel=(0.000000/4.000000/0.000000) angvel=(5.000000/10.000000/0.000000) explode=+debris_exp damage=5.000000 damageclass=0x1 typeflags=0xc ",
"_debris2         _debris          explode=+smflash ",
"shrapnel2_1      _debris2         model3d=shrp_1.3do size=0.045000 movesize=0.045000 ",
"shrapnel2_2      _debris2         model3d=shrp_2.3do size=0.040000 movesize=0.040000 ",
"shrapnel2_3      _debris2         model3d=shrp_3.3do size=0.028000 movesize=0.028000 ",
"shrapnel2_4      _debris2         model3d=shrp_4.3do size=0.026000 movesize=0.026000 ",
"+sequencer_exp   _explosion       thingflags=0x1 light=0.200000 timer=0.800000 sprite=seqx2.spr soundclass=exp_med.snd creatething=+firecloud2 typeflags=0x17 damage=100.000000 blasttime=0.700000 force=300.000000 maxlight=0.800000 range=0.600000 debris=shrapnel2_1 debris=shrapnel2_2 debris=shrapnel2_3 debris=shrapnel2_4 ",
"+seqchrg         +grenade2        timer=1.000000 model3d=seq0.3do size=0.010000 movesize=0.010000 soundclass=seq.snd surfdrag=5.000000 airdrag=1.000000 physflags=0x29d vel=(0.000000/0.100000/0.000000) angvel=(0.000000/0.000000/0.000000) buoyancy=0.150000 explode=+sequencer_exp fleshhit=+sequencer_exp typeflags=0x40380 ",
"+seqchrg2        +seqchrg         thingflags=0x20000400 timer=60.000003 cog=class_sequencer.cog ",
"shrapnel_1       _debris          model3d=shrp_1.3do size=0.045000 movesize=0.045000 ",
"shrapnel_2       _debris          model3d=shrp_2.3do size=0.040000 movesize=0.040000 ",
"shrapnel_3       _debris          model3d=shrp_3.3do size=0.028000 movesize=0.028000 ",
"shrapnel_4       _debris          model3d=shrp_4.3do size=0.026000 movesize=0.026000 ",
"+raildet_exp     _explosion       thingflags=0x1 light=0.200000 timer=0.500000 sprite=rldx.spr soundclass=exp_raildet.snd typeflags=0x17 damage=110.000000 blasttime=0.700000 force=300.000000 maxlight=0.800000 range=0.500000 debris=shrapnel_1 debris=shrapnel_2 debris=shrapnel_3 debris=shrapnel_4 ",
"+raildet2        +grenade1        thingflags=0x20000400 timer=2.500000 model3d=rld0.3do size=0.003000 movesize=0.003000 puppet=ra.pup soundclass=rail.snd creatething=+lgflash cog=00_smoketrail.cog airdrag=0.000000 height=0.003000 physflags=0x200 vel=(0.000000/2.500000/0.000000) angvel=(0.000000/0.000000/90.000000) explode=+raildet_exp fleshhit=+raildet_exp damage=5.000000 typeflags=0x240b81 ",
"+raildet_exp2    +raildet_exp     debris=shrapnel_1 debris=shrapnel_2 debris=shrapnel_3 debris=shrapnel_4 ",
"+raildet         +raildet2        timer=10.000000 explode=+raildet_exp2 fleshhit=+raildet_exp2 damage=20.000000 typeflags=0x24020d ",
"+conccloud       +dustcloud       rate=512.000000 maxthrust=100.000000 count=256 minsize=0.012000 pitchrange=5.000000 ",
"+conc_exp        _explosion       thingflags=0x1 light=0.300000 timer=1.000000 sprite=conx.spr soundclass=exp_conc.snd creatething=+conccloud typeflags=0x17 damage=80.000000 blasttime=1.000000 force=200.000000 maxlight=0.800000 range=0.800000 ",
"+concbullet      _weapon          thingflags=0x20000001 model3d=con0.3do size=0.005000 movesize=0.005000 soundclass=conc.snd creatething=+lgflash vel=(0.000000/7.000000/0.000000) explode=+conc_exp fleshhit=+conc_exp damage=20.000000 typeflags=0x20000d ",
"+concblast2p     +dustcloud       orient=(90.000000/0.000000/0.000000) range=0.001500 rate=128.000000 elementsize=0.005000 count=64 minsize=0.001200 pitchrange=5.000000 ",
"+concblast3p     +concblast2p     typeflags=0x2b material=00ramp4.mat maxthrust=100.000000 ",
"+concblast2      _weapon          size=0.005000 movesize=0.005000 fleshhit=+concblast3p trailthing=+concblast2p elementsize=0.300000 damage=80.000000 mindamage=20.000000 typeflags=0xa00d range=5.000000 rate=1.000000 ",
"+axe_exp         _explosion       timer=0.001000 soundclass=exp_axe.snd typeflags=0x0 ",
"+gamaxe          _weapon          size=0.001000 movesize=0.001000 mass=100.000000 explode=+axe_exp fleshhit=+axe_exp damage=40.000000 damageclass=0x1 typeflags=0x200d range=0.250000 force=50.000000 ",
"+force_repel     _explosion       thingflags=0x1 light=0.500000 timer=0.400000 soundclass=exp_dest.snd typeflags=0x52 blasttime=0.300000 force=200.000000 maxlight=1.000000 range=0.500000 ",
"+force_ltpeice   none             orient=(0.000000/0.000000/0.000000) type=weapon move=physics timer=0.250000 model3d=ligt2.3do size=0.005000 movesize=0.005000 physflags=0x200 maxrotvel=360.000000 angvel=(0.000000/0.000000/360.000000) ",
"+lightninghit    none             orient=(0.000000/0.000000/0.000000) type=particle move=physics timer=0.200000 typeflags=0x2b material=00ramp4.mat range=0.020000 rate=16.000000 maxthrust=8.000000 elementsize=0.003000 count=16 ",
"+force_lightning _weapon          thingflags=0x1 light=0.100000 timer=0.100000 size=0.005000 movesize=0.005000 vel=(0.000000/1.000000/0.000000) angvel=(0.000000/0.000000/360.000000) explode=+lightninghit fleshhit=+lightninghit trailthing=+force_ltpeice elementsize=0.075000 trailcylradius=0.050000 trailrandangle=30.000000 damage=13.000000 damageclass=0x8 typeflags=0x1840d range=1.500000 ",
"+force_lightning2 +force_lightning damage=15.000000 ",
"+force_lightning3 +force_lightning damage=20.000000 ",
"+force_lightning4 +force_lightning damage=25.000000 ",
"lightsaber       _powerup         thingflags=0x400 model3d=sabp.3do cog=pow_saber.cog ",
"+force_saber     _weapon          thingflags=0x20000001 light=0.100000 timer=1.000000 model3d=sab0.3do size=0.005000 movesize=0.005000 vel=(0.000000/1.000000/0.000000) angvel=(0.000000/150.000000/0.000000) explode=lightsaber fleshhit=lightsaber damage=50.000000 damageclass=0x10 typeflags=0x40d ",
"+force_shield    none             orient=(0.000000/0.000000/0.000000) type=cog move=physics timer=61.000003 particle=sphere.par angvel=(60.000000/60.000000/60.000000) ",
"+force_blind     +dustcloud       material=00teleport.mat range=0.050000 rate=32.000000 elementsize=0.003000 minsize=0.020000 pitchrange=1.000000 yawrange=1.000000 ",
"+smoke           none             orient=(0.000000/0.000000/0.000000) type=particle move=physics timer=0.800000 physflags=0x20000 vel=(0.000000/0.000000/0.120000) angvel=(0.000000/90.000000/0.000000) typeflags=0x3e material=00gsmoke.mat range=0.030000 elementsize=0.005000 count=8 ",
"+dest_trail      +smoke           vel=(0.000000/0.000000/0.000000) material=dstructparts.mat ",
"+dest_cloud      +firecloud       material=dstructparts.mat ",
"+force_dest1     _explosion       thingflags=0x1 light=0.100000 timer=0.400000 sprite=destruct8.spr soundclass=exp_dest.snd creatething=+dest_cloud typeflags=0x53 damage=15.000000 damageclass=0x8 blasttime=0.300000 force=100.000000 maxlight=0.500000 range=0.500000 ",
"+force_dest2     _explosion       thingflags=0x1 light=0.200000 timer=0.600000 sprite=destruct8.spr soundclass=exp_dest.snd creatething=+dest_cloud typeflags=0x53 damage=30.000000 damageclass=0x8 blasttime=0.400000 force=200.000000 maxlight=0.600000 range=1.000000 ",
"+force_dest3     _explosion       thingflags=0x1 light=0.300000 timer=0.800000 sprite=destruct8.spr soundclass=exp_dest.snd creatething=+dest_cloud typeflags=0x53 damage=45.000000 damageclass=0x8 blasttime=0.500000 force=300.000000 maxlight=0.700000 range=1.500000 ",
"+force_dest4     _explosion       thingflags=0x1 light=0.400000 timer=1.000000 sprite=destruct8.spr soundclass=exp_dest.snd creatething=+dest_cloud typeflags=0x53 damage=60.000000 damageclass=0x8 blasttime=0.600000 force=400.000000 maxlight=0.800000 range=2.000000 ",
"+force_dest_p1   _weapon          thingflags=0x20000401 light=0.400000 sprite=forcedstruct_150.spr cog=00_desttrail.cog vel=(0.000000/7.000000/0.000000) explode=+force_dest1 fleshhit=+force_dest1 damage=20.000000 typeflags=0xd ",
"+force_dest_p2   +force_dest_p1   explode=+force_dest2 fleshhit=+force_dest2 ",
"+force_dest_p3   +force_dest_p1   explode=+force_dest3 fleshhit=+force_dest3 ",
"+force_dest_p4   +force_dest_p1   explode=+force_dest4 fleshhit=+force_dest4 ",
"+force_heal      none             orient=(0.000000/0.000000/0.000000) type=particle move=physics timer=2.000000 angvel=(90.000000/90.000000/90.000000) typeflags=0x3f material=00teleport.mat range=0.300000 rate=128.000000 maxthrust=0.010000 elementsize=0.003000 count=128 ",
"+heavysmoke      +smoke           timer=1.600000 range=0.100000 rate=32.000000 count=64 ",
"+twinkle         none             orient=(0.000000/0.000000/0.000000) type=explosion thingflags=0x1 timer=0.500000 sprite=twinkle.spr typeflags=0x11 ",
"+sspks_wall      none             orient=(0.000000/0.000000/0.000000) type=particle move=physics timer=0.100000 mass=0.050000 physflags=0x400201 vel=(0.000000/0.000000/0.150000) typeflags=0x2b material=00ramp1.mat range=0.030000 rate=4.000000 maxthrust=8.000000 elementsize=0.003000 count=48 ",
"+ssparks_wall    _explosion       thingflags=0x1 light=0.300000 timer=0.800000 soundclass=exp_saber_wall.snd creatething=+sspks_wall typeflags=0x112 blasttime=0.700000 maxlight=0.500000 flashrgb=(80/90/80) ",
"+sspks_blood     none             orient=(0.000000/0.000000/0.000000) type=particle move=physics timer=0.200000 mass=0.100000 physflags=0x400201 vel=(0.000000/0.000000/0.200000) typeflags=0x2b material=00ramp2.mat range=0.040000 rate=4.000000 maxthrust=9.000000 elementsize=0.005000 count=24 ",
"+ssparks_blood   _explosion       thingflags=0x1 light=0.100000 timer=0.800000 soundclass=exp_saber_blood.snd creatething=+sspks_blood typeflags=0x12 blasttime=0.700000 maxlight=0.300000 ",
"+sspks_saber     none             orient=(0.000000/0.000000/0.000000) type=particle move=physics timer=0.300000 mass=0.050000 physflags=0x400200 vel=(0.000000/0.000000/0.100000) typeflags=0x27 material=00teleport.mat range=0.020000 rate=32.000000 maxthrust=8.000000 elementsize=0.003000 count=32 ",
"+ssparks_saber   _explosion       thingflags=0x1 light=0.800000 timer=0.800000 soundclass=exp_saber_saber.snd creatething=+sspks_saber typeflags=0x112 blasttime=0.700000 maxlight=1.000000 flashrgb=(150/160/150) ",
"_droppowerup     _powerup         timer=30.000001 height=0.011000 physflags=0x41 typeflags=0x0 ",
"+backpack        _droppowerup     thingflags=0x400 model3d=bpck.3do cog=pow_backpack.cog height=0.036337 typeflags=0x4 ",
"bryarpistol      _powerup         thingflags=0x400 model3d=bryp.3do cog=pow_bryar.cog ",
"singledetonator  _powerup         thingflags=0x400 model3d=detp_1.3do cog=pow_single_thermal.cog ",
"crossbow         _powerup         thingflags=0x400 model3d=bowp.3do cog=pow_crossbow.cog ",
"singleseqcharge  _powerup         thingflags=0x400 model3d=seqp_1.3do cog=pow_single_sequencer.cog ",
"+fpbryarpistol   bryarpistol      collide=0 timer=4.000000 typeflags=0x0 respawn=0.000000 ",
"+fpstrifle       strifle          collide=0 timer=4.000000 typeflags=0x0 respawn=0.000000 ",
"+fpdetonator     singledetonator  collide=0 timer=4.000000 typeflags=0x0 respawn=0.000000 ",
"+fpcrossbow      crossbow         collide=0 timer=4.000000 typeflags=0x0 respawn=0.000000 ",
"+fprepeatergun   repeatergun      collide=0 timer=4.000000 typeflags=0x0 respawn=0.000000 ",
"+fprailgun       railgun          collide=0 timer=4.000000 typeflags=0x0 respawn=0.000000 ",
"+fpseqcharge     singleseqcharge  collide=0 timer=4.000000 typeflags=0x0 respawn=0.000000 ",
"+fpconcrifle     concrifle        collide=0 timer=4.000000 typeflags=0x0 respawn=0.000000 ",
"+telesparks      none             orient=(0.000000/0.000000/0.000000) type=particle timer=0.120000 typeflags=0x3f material=00teleport.mat range=0.030000 rate=256.000000 maxthrust=80.000000 elementsize=0.002000 count=256 ",
"bubble           none             orient=(0.000000/0.000000/0.000000) type=cog move=physics thingflags=0x10000000 timer=3.000000 sprite=bubble.spr mass=0.050000 physflags=0x200 vel=(0.000000/0.000000/0.300000) ",
"bubble2          bubble           sprite=bubble2.spr vel=(0.000000/0.000000/0.450000) ",
"bubble3          bubble           sprite=bubble3.spr vel=(0.000000/0.000000/0.600000) ",
"+watersplash     none             orient=(0.000000/0.000000/0.000000) type=explosion timer=0.500000 sprite=splash.spr typeflags=0x1 damageclass=0x4 ",
"+watersplash2    +watersplash     sprite=splooshx.spr ",
"shrapnel_5       _debris          model3d=shrp_5.3do size=0.084000 movesize=0.084000 ",
"+xtank1_exp      _explosion       thingflags=0x1 light=0.200000 timer=0.800000 sprite=detx.spr soundclass=exp_probe.snd typeflags=0x17 damage=90.000000 blasttime=0.700000 force=100.000000 maxlight=0.800000 range=0.450000 debris=shrapnel_1 debris=shrapnel_2 debris=shrapnel_3 debris=shrapnel_5 ",
"+xtank3_exp      +xtank1_exp      sprite=tiex.spr soundclass=exp_tie.snd damage=200.000000 force=200.000000 range=0.600000 debris=shrapnel_1 debris=shrapnel_2 debris=shrapnel_3 debris=shrapnel_5 ",
"_civilian        _humanactor      surfdrag=2.000000 mass=100.000000 maxvel=0.300000 maxthrust=2.00 maxrotthrust=90.00 typeflags=0x180000",
"_humanactor      _actor           size=0.065000 movesize=0.065000 surfdrag=3.000000 airdrag=0.500000 maxvel=0.500000 maxthrust=0.80 typeflags=0x80000",
]

jkl_path = Path(sys.argv[1])

f_out = open(str(jkl_path).replace(".jkl", "_fixed.jkl"), "w")
f = open(str(jkl_path), "r")
lines = f.read().split("\n")
f.close()

cur_fixing = ""
i = 0
while True:
    if i >= len(lines): break

    l = lines[i]
    i += 1
    if "World sounds" in l:
        snd_list = []
        to_skip = i
        for j in range(i, len(lines)):
            to_skip = j
            if lines[j] == "": continue
            if lines[j] == "end": break
            snd_list += [lines[j]]

        snd_list += sounds_inject

        f_out.write("World sounds " + str(len(snd_list) + 64) + "\n")
        f_out.write("\n")
        for s in snd_list:
            f_out.write(s + "\n")
        f_out.write("end\n")
        i = to_skip+1
        continue

    if "World materials" in l:
        mat_list = []
        to_skip = i
        for j in range(i, len(lines)):
            to_skip = j
            if len(lines[j]) == 0 or lines[j][0] == '#': continue
            if lines[j] == "end": break
            mat_list += [lines[j].split(":\t")[1]]

        mat_list += mat_inject

        f_out.write("World materials " + str(len(mat_list) + 32) + "\n")
        f_out.write("\n")
        idx = 0
        for m in mat_list:
            f_out.write(str(idx) + ":\t" + m + "\n")
            idx += 1
        f_out.write("end\n")
        i = to_skip+1
        continue

    if "World models" in l:
        ent_list = []
        to_skip = i
        for j in range(i, len(lines)):
            to_skip = j
            if len(lines[j]) == 0 or lines[j][0] == '#': continue
            if lines[j] == "end": break
            ent_list += [lines[j].split(":\t")[1]]

        ent_list += model_inject

        f_out.write("World models " + str(len(ent_list) + 32) + "\n")
        f_out.write("\n")
        idx = 0
        for m in ent_list:
            f_out.write(str(idx) + ":\t" + m + "\n")
            idx += 1
        f_out.write("end\n")
        i = to_skip+1
        continue

    if "World sprites" in l:
        ent_list = []
        to_skip = i
        for j in range(i, len(lines)):
            to_skip = j
            if len(lines[j]) == 0 or lines[j][0] == '#': continue
            if lines[j] == "end": break
            ent_list += [lines[j].replace("\t", " ").split(": ")[1]]

        ent_list += sprite_inject

        f_out.write("World sprites " + str(len(ent_list) + 0) + "\n")
        f_out.write("\n")
        idx = 0
        for m in ent_list:
            f_out.write(str(idx) + ":\t" + m + "\n")
            idx += 1
        f_out.write("end\n")
        i = to_skip+1
        continue

    if "World keyframes" in l:
        ent_list = []
        to_skip = i
        for j in range(i, len(lines)):
            to_skip = j
            if len(lines[j]) == 0 or lines[j][0] == '#': continue
            if lines[j] == "end": break
            ent_list += [lines[j].split(":\t")[1]]

        ent_list += key_inject

        f_out.write("World keyframes " + str(len(ent_list) + 32) + "\n")
        f_out.write("\n")
        idx = 0
        for m in ent_list:
            f_out.write(str(idx) + ":\t" + m + "\n")
            idx += 1
        f_out.write("end\n")
        i = to_skip+1
        continue

    if "World puppets" in l:
        ent_list = []
        to_skip = i
        for j in range(i, len(lines)):
            to_skip = j
            if len(lines[j]) == 0 or lines[j][0] == '#': continue
            if lines[j] == "end": break
            ent_list += [lines[j].split(":\t")[1]]

        ent_list += pup_inject

        f_out.write("World puppets " + str(len(ent_list) + 0) + "\n")
        f_out.write("\n")
        idx = 0
        for m in ent_list:
            f_out.write(str(idx) + ":\t" + m + "\n")
            idx += 1
        f_out.write("end\n")
        i = to_skip+1
        continue

    if "World soundclasses" in l:
        ent_list = []
        to_skip = i
        for j in range(i, len(lines)):
            to_skip = j
            if len(lines[j]) == 0 or lines[j][0] == '#': continue
            if lines[j] == "end": break
            ent_list += [lines[j].split(":\t")[1]]

        ent_list += snd_inject

        f_out.write("World soundclasses " + str(len(ent_list) + 0) + "\n")
        f_out.write("\n")
        idx = 0
        for m in ent_list:
            f_out.write(str(idx) + ":\t" + m + "\n")
            idx += 1
        f_out.write("end\n")
        i = to_skip+1
        continue

    if "World scripts" in l:
        ent_list = []
        to_skip = i
        for j in range(i, len(lines)):
            to_skip = j
            if len(lines[j]) == 0 or lines[j][0] == '#': continue
            if lines[j] == "end": break
            ent_list += [lines[j].split(":\t")[1]]

        ent_list += cog_inject

        f_out.write("World scripts " + str(len(ent_list) + 0) + "\n")
        f_out.write("\n")
        idx = 0
        for m in ent_list:
            f_out.write(str(idx) + ":\t" + m + "\n")
            idx += 1
        f_out.write("end\n")
        i = to_skip+1
        continue

    if "World templates" in l:
        ent_list = []
        to_skip = i
        for j in range(i, len(lines)):
            to_skip = j
            if len(lines[j]) == 0 or lines[j][0] == '#': continue
            if lines[j] == "end": break
            ent_list += [lines[j]]

        needs_remove = []
        for inj in template_inject:
            inj_name = inj.replace("\t", " ").split(" ")[0]
            found_line = ""
            idx = 0
            for e in ent_list:
                name = e.replace("\t", " ").split(" ")[0]
                if name == inj_name:
                    found_line = idx
                    break
                idx += 1
            if found_line != "":
                print("Superceding", inj_name)
                ent_list[found_line] = inj
                needs_remove += [inj]
        for inj in needs_remove:
            template_inject.remove(inj)
        ent_list += template_inject

        f_out.write("World templates " + str(len(ent_list) + 0) + "\n")
        f_out.write("\n")
        idx = 0
        for m in ent_list:
            f_out.write(m + "\n")
            idx += 1
        f_out.write("end\n")
        i = to_skip+1
        continue

    f_out.write(l + "\n")

f_out.close()