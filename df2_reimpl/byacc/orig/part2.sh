#! /bin/sh
# This is a shell archive.  Remove anything before this line, then unpack
# it by saving it into a file and typing "sh file".  To overwrite existing
# files, type "sh file -c".  You can also feed this as standard input via
# unshar, or by typing "sh <file", e.g..  If this archive is complete, you
# will see the following message at the end:
#		"End of archive 2 (of 5)."
# Contents:  lalr.c lr0.c mkpar.c skeleton.c
# Wrapped by rsalz@litchi.bbn.com on Mon Apr  2 11:43:42 1990
PATH=/bin:/usr/bin:/usr/ucb ; export PATH
if test -f 'lalr.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'lalr.c'\"
else
echo shar: Extracting \"'lalr.c'\" \(10213 characters\)
sed "s/^X//" >'lalr.c' <<'END_OF_FILE'
X#include "defs.h"
X
Xtypedef
X  struct shorts
X    {
X      struct shorts *next;
X      short value;
X    }
X  shorts;
X
Xint tokensetsize;
Xshort *lookaheads;
Xshort *LAruleno;
Xunsigned *LA;
Xshort *accessing_symbol;
Xcore **state_table;
Xshifts **shift_table;
Xreductions **reduction_table;
Xshort *goto_map;
Xshort *from_state;
Xshort *to_state;
X
Xshort **transpose();
X
Xstatic int infinity;
Xstatic int maxrhs;
Xstatic int ngotos;
Xstatic unsigned *F;
Xstatic short **includes;
Xstatic shorts **lookback;
Xstatic short **R;
Xstatic short *INDEX;
Xstatic short *VERTICES;
Xstatic int top;
X
X
Xlalr()
X{
X    tokensetsize = WORDSIZE(ntokens);
X
X    set_state_table();
X    set_accessing_symbol();
X    set_shift_table();
X    set_reduction_table();
X    set_maxrhs();
X    initialize_LA();
X    set_goto_map();
X    initialize_F();
X    build_relations();
X    compute_FOLLOWS();
X    compute_lookaheads();
X}
X
X
X
Xset_state_table()
X{
X    register core *sp;
X
X    state_table = NEW2(nstates, core *);
X    for (sp = first_state; sp; sp = sp->next)
X	state_table[sp->number] = sp;
X}
X
X
X
Xset_accessing_symbol()
X{
X    register core *sp;
X
X    accessing_symbol = NEW2(nstates, short);
X    for (sp = first_state; sp; sp = sp->next)
X	accessing_symbol[sp->number] = sp->accessing_symbol;
X}
X
X
X
Xset_shift_table()
X{
X    register shifts *sp;
X
X    shift_table = NEW2(nstates, shifts *);
X    for (sp = first_shift; sp; sp = sp->next)
X	shift_table[sp->number] = sp;
X}
X
X
X
Xset_reduction_table()
X{
X    register reductions *rp;
X
X    reduction_table = NEW2(nstates, reductions *);
X    for (rp = first_reduction; rp; rp = rp->next)
X	reduction_table[rp->number] = rp;
X}
X
X
X
Xset_maxrhs()
X{
X  register short *itemp;
X  register short *item_end;
X  register int length;
X  register int max;
X
X  length = 0;
X  max = 0;
X  item_end = ritem + nitems;
X  for (itemp = ritem; itemp < item_end; itemp++)
X    {
X      if (*itemp >= 0)
X	{
X	  length++;
X	}
X      else
X	{
X	  if (length > max) max = length;
X	  length = 0;
X	}
X    }
X
X  maxrhs = max;
X}
X
X
X
Xinitialize_LA()
X{
X  register int i, j, k;
X  register reductions *rp;
X
X  lookaheads = NEW2(nstates + 1, short);
X
X  k = 0;
X  for (i = 0; i < nstates; i++)
X    {
X      lookaheads[i] = k;
X      rp = reduction_table[i];
X      if (rp)
X	k += rp->nreds;
X    }
X  lookaheads[nstates] = k;
X
X  LA = NEW2(k * tokensetsize, unsigned);
X  LAruleno = NEW2(k, short);
X  lookback = NEW2(k, shorts *);
X
X  k = 0;
X  for (i = 0; i < nstates; i++)
X    {
X      rp = reduction_table[i];
X      if (rp)
X	{
X	  for (j = 0; j < rp->nreds; j++)
X	    {
X	      LAruleno[k] = rp->rules[j];
X	      k++;
X	    }
X	}
X    }
X}
X
X
Xset_goto_map()
X{
X  register shifts *sp;
X  register int i;
X  register int symbol;
X  register int k;
X  register short *temp_map;
X  register int state2;
X  register int state1;
X
X  goto_map = NEW2(nvars + 1, short) - ntokens;
X  temp_map = NEW2(nvars + 1, short) - ntokens;
X
X  ngotos = 0;
X  for (sp = first_shift; sp; sp = sp->next)
X    {
X      for (i = sp->nshifts - 1; i >= 0; i--)
X	{
X	  symbol = accessing_symbol[sp->shift[i]];
X
X	  if (ISTOKEN(symbol)) break;
X
X	  if (ngotos == MAXSHORT)
X	    fatal("too many gotos");
X
X	  ngotos++;
X	  goto_map[symbol]++;
X        }
X    }
X
X  k = 0;
X  for (i = ntokens; i < nsyms; i++)
X    {
X      temp_map[i] = k;
X      k += goto_map[i];
X    }
X
X  for (i = ntokens; i < nsyms; i++)
X    goto_map[i] = temp_map[i];
X
X  goto_map[nsyms] = ngotos;
X  temp_map[nsyms] = ngotos;
X
X  from_state = NEW2(ngotos, short);
X  to_state = NEW2(ngotos, short);
X
X  for (sp = first_shift; sp; sp = sp->next)
X    {
X      state1 = sp->number;
X      for (i = sp->nshifts - 1; i >= 0; i--)
X	{
X	  state2 = sp->shift[i];
X	  symbol = accessing_symbol[state2];
X
X	  if (ISTOKEN(symbol)) break;
X
X	  k = temp_map[symbol]++;
X	  from_state[k] = state1;
X	  to_state[k] = state2;
X	}
X    }
X
X  FREE(temp_map + ntokens);
X}
X
X
X
X/*  Map_goto maps a state/symbol pair into its numeric representation.	*/
X
Xint
Xmap_goto(state, symbol)
Xint state;
Xint symbol;
X{
X    register int high;
X    register int low;
X    register int middle;
X    register int s;
X
X    low = goto_map[symbol];
X    high = goto_map[symbol + 1];
X
X    for (;;)
X    {
X	assert(low <= high);
X	middle = (low + high) >> 1;
X	s = from_state[middle];
X	if (s == state)
X	    return (middle);
X	else if (s < state)
X	    low = middle + 1;
X	else
X	    high = middle - 1;
X    }
X}
X
X
X
Xinitialize_F()
X{
X  register int i;
X  register int j;
X  register int k;
X  register shifts *sp;
X  register short *edge;
X  register unsigned *rowp;
X  register short *rp;
X  register short **reads;
X  register int nedges;
X  register int stateno;
X  register int symbol;
X  register int nwords;
X
X  nwords = ngotos * tokensetsize;
X  F = NEW2(nwords, unsigned);
X
X  reads = NEW2(ngotos, short *);
X  edge = NEW2(ngotos + 1, short);
X  nedges = 0;
X
X  rowp = F;
X  for (i = 0; i < ngotos; i++)
X    {
X      stateno = to_state[i];
X      sp = shift_table[stateno];
X
X      if (sp)
X	{
X	  k = sp->nshifts;
X
X	  for (j = 0; j < k; j++)
X	    {
X	      symbol = accessing_symbol[sp->shift[j]];
X	      if (ISVAR(symbol))
X		break;
X	      SETBIT(rowp, symbol);
X	    }
X
X	  for (; j < k; j++)
X	    {
X	      symbol = accessing_symbol[sp->shift[j]];
X	      if (nullable[symbol])
X		edge[nedges++] = map_goto(stateno, symbol);
X	    }
X	
X	  if (nedges)
X	    {
X	      reads[i] = rp = NEW2(nedges + 1, short);
X
X	      for (j = 0; j < nedges; j++)
X		rp[j] = edge[j];
X
X	      rp[nedges] = -1;
X	      nedges = 0;
X	    }
X	}
X
X      rowp += tokensetsize;
X    }
X
X  SETBIT(F, 0);
X  digraph(reads);
X
X  for (i = 0; i < ngotos; i++)
X    {
X      if (reads[i])
X	FREE(reads[i]);
X    }
X
X  FREE(reads);
X  FREE(edge);
X}
X
X
X
Xbuild_relations()
X{
X  register int i;
X  register int j;
X  register int k;
X  register short *rulep;
X  register short *rp;
X  register shifts *sp;
X  register int length;
X  register int nedges;
X  register int done;
X  register int state1;
X  register int stateno;
X  register int symbol1;
X  register int symbol2;
X  register short *shortp;
X  register short *edge;
X  register short *states;
X  register short **new_includes;
X
X  includes = NEW2(ngotos, short *);
X  edge = NEW2(ngotos + 1, short);
X  states = NEW2(maxrhs + 1, short);
X
X  for (i = 0; i < ngotos; i++)
X    {
X      nedges = 0;
X      state1 = from_state[i];
X      symbol1 = accessing_symbol[to_state[i]];
X
X      for (rulep = derives[symbol1]; *rulep >= 0; rulep++)
X	{
X	  length = 1;
X	  states[0] = state1;
X	  stateno = state1;
X
X	  for (rp = ritem + rrhs[*rulep]; *rp >= 0; rp++)
X	    {
X	      symbol2 = *rp;
X	      sp = shift_table[stateno];
X	      k = sp->nshifts;
X
X	      for (j = 0; j < k; j++)
X		{
X		  stateno = sp->shift[j];
X		  if (accessing_symbol[stateno] == symbol2) break;
X		}
X
X	      states[length++] = stateno;
X	    }
X
X	  add_lookback_edge(stateno, *rulep, i);
X
X	  length--;
X	  done = 0;
X	  while (!done)
X	    {
X	      done = 1;
X	      rp--;
X	      if (ISVAR(*rp))
X		{
X		  stateno = states[--length];
X		  edge[nedges++] = map_goto(stateno, *rp);
X		  if (nullable[*rp] && length > 0) done = 0;
X		}
X	    }
X	}
X
X      if (nedges)
X	{
X	  includes[i] = shortp = NEW2(nedges + 1, short);
X	  for (j = 0; j < nedges; j++)
X	    shortp[j] = edge[j];
X	  shortp[nedges] = -1;
X	}
X    }
X
X  new_includes = transpose(includes, ngotos);
X
X  for (i = 0; i < ngotos; i++)
X    if (includes[i])
X      FREE(includes[i]);
X
X  FREE(includes);
X
X  includes = new_includes;
X
X  FREE(edge);
X  FREE(states);
X}
X
X
Xadd_lookback_edge(stateno, ruleno, gotono)
Xint stateno, ruleno, gotono;
X{
X    register int i, k;
X    register int found;
X    register shorts *sp;
X
X    i = lookaheads[stateno];
X    k = lookaheads[stateno + 1];
X    found = 0;
X    while (!found && i < k)
X    {
X	if (LAruleno[i] == ruleno)
X	    found = 1;
X	else
X	    ++i;
X    }
X    assert(found);
X
X    sp = NEW(shorts);
X    sp->next = lookback[i];
X    sp->value = gotono;
X    lookback[i] = sp;
X}
X
X
X
Xshort **
Xtranspose(R, n)
Xshort **R;
Xint n;
X{
X  register short **new_R;
X  register short **temp_R;
X  register short *nedges;
X  register short *sp;
X  register int i;
X  register int k;
X
X  nedges = NEW2(n, short);
X
X  for (i = 0; i < n; i++)
X    {
X      sp = R[i];
X      if (sp)
X	{
X	  while (*sp >= 0)
X	    nedges[*sp++]++;
X	}
X    }
X
X  new_R = NEW2(n, short *);
X  temp_R = NEW2(n, short *);
X
X  for (i = 0; i < n; i++)
X    {
X      k = nedges[i];
X      if (k > 0)
X	{
X	  sp = NEW2(k + 1, short);
X	  new_R[i] = sp;
X	  temp_R[i] = sp;
X	  sp[k] = -1;
X	}
X    }
X
X  FREE(nedges);
X
X  for (i = 0; i < n; i++)
X    {
X      sp = R[i];
X      if (sp)
X	{
X	  while (*sp >= 0)
X	    *temp_R[*sp++]++ = i;
X	}
X    }
X
X  FREE(temp_R);
X
X  return (new_R);
X}
X
X
X
Xcompute_FOLLOWS()
X{
X  digraph(includes);
X}
X
X
Xcompute_lookaheads()
X{
X  register int i, n;
X  register unsigned *fp1, *fp2, *fp3;
X  register shorts *sp, *next;
X  register unsigned *rowp;
X
X  rowp = LA;
X  n = lookaheads[nstates];
X  for (i = 0; i < n; i++)
X    {
X      fp3 = rowp + tokensetsize;
X      for (sp = lookback[i]; sp; sp = sp->next)
X	{
X	  fp1 = rowp;
X	  fp2 = F + tokensetsize * sp->value;
X	  while (fp1 < fp3)
X	    *fp1++ |= *fp2++;
X	}
X      rowp = fp3;
X    }
X
X  for (i = 0; i < n; i++)
X    for (sp = lookback[i]; sp; sp = next)
X      {
X        next = sp->next;
X        FREE(sp);
X      }
X
X  FREE(lookback);
X  FREE(F);
X}
X
X
Xdigraph(relation)
Xshort **relation;
X{
X  register int i;
X
X  infinity = ngotos + 2;
X  INDEX = NEW2(ngotos + 1, short);
X  VERTICES = NEW2(ngotos + 1, short);
X  top = 0;
X
X  R = relation;
X
X  for (i = 0; i < ngotos; i++)
X    INDEX[i] = 0;
X
X  for (i = 0; i < ngotos; i++)
X    {
X      if (INDEX[i] == 0 && R[i])
X	traverse(i);
X    }
X
X  FREE(INDEX);
X  FREE(VERTICES);
X}
X
X
X
Xtraverse(i)
Xregister int i;
X{
X  register unsigned *fp1;
X  register unsigned *fp2;
X  register unsigned *fp3;
X  register int j;
X  register short *rp;
X
X  int height;
X  unsigned *base;
X
X  VERTICES[++top] = i;
X  INDEX[i] = height = top;
X
X  base = F + i * tokensetsize;
X  fp3 = base + tokensetsize;
X
X  rp = R[i];
X  if (rp)
X    {
X      while ((j = *rp++) >= 0)
X	{
X	  if (INDEX[j] == 0)
X	    traverse(j);
X
X	  if (INDEX[i] > INDEX[j])
X	    INDEX[i] = INDEX[j];
X
X	  fp1 = base;
X	  fp2 = F + j * tokensetsize;
X
X	  while (fp1 < fp3)
X	    *fp1++ |= *fp2++;
X	}
X    }
X
X  if (INDEX[i] == height)
X    {
X      for (;;)
X	{
X	  j = VERTICES[top--];
X	  INDEX[j] = infinity;
X
X	  if (i == j)
X	    break;
X
X	  fp1 = base;
X	  fp2 = F + j * tokensetsize;
X
X	  while (fp1 < fp3)
X	    *fp2++ = *fp1++;
X	}
X    }
X}
END_OF_FILE
if [[ 10213 -ne `wc -c <'lalr.c'` ]]; then
    echo shar: \"'lalr.c'\" unpacked with wrong size!
fi
# end of 'lalr.c'
fi
if test -f 'lr0.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'lr0.c'\"
else
echo shar: Extracting \"'lr0.c'\" \(9615 characters\)
sed "s/^X//" >'lr0.c' <<'END_OF_FILE'
X#include "defs.h"
X
Xextern short *itemset;
Xextern short *itemsetend;
Xextern unsigned *ruleset;
X
Xint nstates;
Xcore *first_state;
Xshifts *first_shift;
Xreductions *first_reduction;
X
Xint get_state();
Xcore *new_state();
X
Xstatic core *this_state;
Xstatic core *last_state;
Xstatic shifts *last_shift;
Xstatic reductions *last_reduction;
X
Xstatic int nshifts;
Xstatic short *shift_symbol;
X
Xstatic short *redset;
Xstatic short *shiftset;
X
Xstatic short **kernel_base;
Xstatic short **kernel_end;
Xstatic short *kernel_items;
X
Xstatic core **state_table;
X
X
Xallocate_itemsets()
X{
X  register short *itemp;
X  register short *item_end;
X  register int symbol;
X  register int i;
X  register int count;
X  register int max;
X  register short *symbol_count;
X
X  count = 0;
X  symbol_count = NEW2(nsyms, short);
X
X  item_end = ritem + nitems;
X  for (itemp = ritem; itemp < item_end; itemp++)
X    {
X      symbol = *itemp;
X      if (symbol >= 0)
X	{
X	  count++;
X	  symbol_count[symbol]++;
X	}
X    }
X
X  kernel_base = NEW2(nsyms, short *);
X  kernel_items = NEW2(count, short);
X
X  count = 0;
X  max = 0;
X  for (i = 0; i < nsyms; i++)
X    {
X      kernel_base[i] = kernel_items + count;
X      count += symbol_count[i];
X      if (max < symbol_count[i])
X	max = symbol_count[i];
X    }
X
X  shift_symbol = symbol_count;
X  kernel_end = NEW2(nsyms, short *);
X}
X
X
X
Xallocate_storage()
X{
X  allocate_itemsets();
X
X  shiftset = NEW2(nsyms, short);
X  redset = NEW2(nrules + 1, short);
X  state_table = NEW2(nitems, core *);
X}
X
X
X
Xappend_states()
X{
X  register int i;
X  register int j;
X  register int symbol;
X
X#ifdef	TRACE
X  fprintf(stderr, "Entering append_states\n");
X#endif
X
X  for (i = 1; i < nshifts; i++)
X    {
X      symbol = shift_symbol[i];
X      j = i;
X      while (j > 0 && shift_symbol[j - 1] > symbol)
X	{
X	  shift_symbol[j] = shift_symbol[j - 1];
X	  j--;
X	}
X      shift_symbol[j] = symbol;
X    }
X
X  for (i = 0; i < nshifts; i++)
X    {
X      symbol = shift_symbol[i];
X      shiftset[i] = get_state(symbol);
X    }
X}
X
X
Xfree_storage()
X{
X  FREE(shift_symbol);
X  FREE(redset);
X  FREE(shiftset);
X  FREE(kernel_base);
X  FREE(kernel_end);
X  FREE(kernel_items);
X  FREE(state_table);
X}
X
X
X
Xgenerate_states()
X{
X  allocate_storage();
X  itemset = NEW2(nitems, short);
X  ruleset = NEW2(WORDSIZE(nrules), unsigned);
X  set_first_derives();
X  initialize_states();
X
X  while (this_state)
X    {
X      closure(this_state->items, this_state->nitems);
X      save_reductions();
X      new_itemsets();
X      append_states();
X
X      if (nshifts > 0)
X        save_shifts();
X
X      this_state = this_state->next;
X    }
X
X  finalize_closure();
X  free_storage();
X}
X
X
X
Xint
Xget_state(symbol)
Xint symbol;
X{
X  register int key;
X  register short *isp1;
X  register short *isp2;
X  register short *iend;
X  register core *sp;
X  register int found;
X
X  int n;
X
X#ifdef	TRACE
X  fprintf(stderr, "Entering get_state, symbol = %d\n", symbol);
X#endif
X
X  isp1 = kernel_base[symbol];
X  iend = kernel_end[symbol];
X  n = iend - isp1;
X
X  key = *isp1;
X  assert(0 <= key && key < nitems);
X  sp = state_table[key];
X  if (sp)
X    {
X      found = 0;
X      while (!found)
X	{
X	  if (sp->nitems == n)
X	    {
X	      found = 1;
X	      isp1 = kernel_base[symbol];
X	      isp2 = sp->items;
X
X	      while (found && isp1 < iend)
X		{
X		  if (*isp1++ != *isp2++)
X		    found = 0;
X		}
X	    }
X
X	  if (!found)
X	    {
X	      if (sp->link)
X		{
X		  sp = sp->link;
X		}
X	      else
X		{
X		  sp = sp->link = new_state(symbol);
X		  found = 1;
X		}
X	    }
X	}
X    }
X  else
X    {
X      state_table[key] = sp = new_state(symbol);
X    }
X
X  return (sp->number);
X}
X
X
X
Xinitialize_states()
X{
X    register int i;
X    register short *start_derives;
X    register core *p;
X
X    start_derives = derives[start_symbol];
X    for (i = 0; start_derives[i] >= 0; ++i)
X	continue;
X
X    p = (core *) MALLOC(sizeof(core) + i*sizeof(short));
X    if (p == 0) no_space();
X
X    p->next = 0;
X    p->link = 0;
X    p->number = 0;
X    p->accessing_symbol = 0;
X    p->nitems = i;
X
X    for (i = 0;  start_derives[i] >= 0; ++i)
X	p->items[i] = rrhs[start_derives[i]];
X
X    first_state = last_state = this_state = p;
X    nstates = 1;
X}
X
X
Xnew_itemsets()
X{
X  register int i;
X  register int shiftcount;
X  register short *isp;
X  register short *ksp;
X  register int symbol;
X
X  for (i = 0; i < nsyms; i++)
X    kernel_end[i] = 0;
X
X  shiftcount = 0;
X  isp = itemset;
X  while (isp < itemsetend)
X    {
X      i = *isp++;
X      symbol = ritem[i];
X      if (symbol > 0)
X	{
X          ksp = kernel_end[symbol];
X
X          if (!ksp)
X	    {
X	      shift_symbol[shiftcount++] = symbol;
X	      ksp = kernel_base[symbol];
X	    }
X
X          *ksp++ = i + 1;
X          kernel_end[symbol] = ksp;
X	}
X    }
X
X  nshifts = shiftcount;
X}
X
X
X
Xcore *
Xnew_state(symbol)
Xint symbol;
X{
X  register int n;
X  register core *p;
X  register short *isp1;
X  register short *isp2;
X  register short *iend;
X
X#ifdef	TRACE
X  fprintf(stderr, "Entering new_state, symbol = %d\n", symbol);
X#endif
X
X  if (nstates >= MAXSHORT)
X    fatal("too many states");
X
X  isp1 = kernel_base[symbol];
X  iend = kernel_end[symbol];
X  n = iend - isp1;
X
X  p = (core *) allocate((unsigned) (sizeof(core) + (n - 1) * sizeof(short)));
X  p->accessing_symbol = symbol;
X  p->number = nstates;
X  p->nitems = n;
X
X  isp2 = p->items;
X  while (isp1 < iend)
X    *isp2++ = *isp1++;
X
X  last_state->next = p;
X  last_state = p;
X
X  nstates++;
X
X  return (p);
X}
X
X
X/* show_cores is used for debugging */
X
Xshow_cores()
X{
X    core *p;
X    int i, j, k, n;
X    int itemno;
X
X    k = 0;
X    for (p = first_state; p; ++k, p = p->next)
X    {
X	if (k) printf("\n");
X	printf("state %d, number = %d, accessing symbol = %s\n",
X		k, p->number, symbol_name[p->accessing_symbol]);
X	n = p->nitems;
X	for (i = 0; i < n; ++i)
X	{
X	    itemno = p->items[i];
X	    printf("%4d  ", itemno);
X	    j = itemno;
X	    while (ritem[j] >= 0) ++j;
X	    printf("%s :", symbol_name[rlhs[-ritem[j]]]);
X	    j = rrhs[-ritem[j]];
X	    while (j < itemno)
X		printf(" %s", symbol_name[ritem[j++]]);
X	    printf(" .");
X	    while (ritem[j] >= 0)
X		printf(" %s", symbol_name[ritem[j++]]);
X	    printf("\n");
X	    fflush(stdout);
X	}
X    }
X}
X
X
X/* show_ritems is used for debugging */
X
Xshow_ritems()
X{
X    int i;
X
X    for (i = 0; i < nitems; ++i)
X	printf("ritem[%d] = %d\n", i, ritem[i]);
X}
X
X
X/* show_rrhs is used for debugging */
Xshow_rrhs()
X{
X    int i;
X
X    for (i = 0; i < nrules; ++i)
X	printf("rrhs[%d] = %d\n", i, rrhs[i]);
X}
X
X
X/* show_shifts is used for debugging */
X
Xshow_shifts()
X{
X    shifts *p;
X    int i, j, k;
X
X    k = 0;
X    for (p = first_shift; p; ++k, p = p->next)
X    {
X	if (k) printf("\n");
X	printf("shift %d, number = %d, nshifts = %d\n", k, p->number,
X		p->nshifts);
X	j = p->nshifts;
X	for (i = 0; i < j; ++i)
X	    printf("\t%d\n", p->shift[i]);
X    }
X}
X
X
Xsave_shifts()
X{
X  register shifts *p;
X  register short *sp1;
X  register short *sp2;
X  register short *send;
X
X  p = (shifts *) allocate((unsigned) (sizeof(shifts) +
X			(nshifts - 1) * sizeof(short)));
X
X  p->number = this_state->number;
X  p->nshifts = nshifts;
X
X  sp1 = shiftset;
X  sp2 = p->shift;
X  send = shiftset + nshifts;
X
X  while (sp1 < send)
X    *sp2++ = *sp1++;
X
X  if (last_shift)
X    {
X      last_shift->next = p;
X      last_shift = p;
X    }
X  else
X    {
X      first_shift = p;
X      last_shift = p;
X    }
X}
X
X
X
Xsave_reductions()
X{
X  register short *isp;
X  register short *rp1;
X  register short *rp2;
X  register int item;
X  register int count;
X  register reductions *p;
X
X  short *rend;
X
X  count = 0;
X  for (isp = itemset; isp < itemsetend; isp++)
X    {
X      item = ritem[*isp];
X      if (item < 0)
X	{
X	  redset[count++] = -item;
X	}
X    }
X
X  if (count)
X    {
X      p = (reductions *) allocate((unsigned) (sizeof(reductions) +
X					(count - 1) * sizeof(short)));
X
X      p->number = this_state->number;
X      p->nreds = count;
X
X      rp1 = redset;
X      rp2 = p->rules;
X      rend = rp1 + count;
X
X      while (rp1 < rend)
X	*rp2++ = *rp1++;
X
X      if (last_reduction)
X	{
X	  last_reduction->next = p;
X	  last_reduction = p;
X	}
X      else
X	{
X	  first_reduction = p;
X	  last_reduction = p;
X	}
X    }
X}
X
X
Xset_derives()
X{
X  register int i, k;
X  register int lhs;
X  register short *rules;
X
X  derives = NEW2(nsyms, short *);
X  rules = NEW2(nvars + nrules, short);
X
X  k = 0;
X  for (lhs = start_symbol; lhs < nsyms; lhs++)
X    {
X      derives[lhs] = rules + k;
X      for (i = 0; i < nrules; i++)
X	{
X	  if (rlhs[i] == lhs)
X	    {
X	      rules[k] = i;
X	      k++;
X	    }
X	}
X      rules[k] = -1;
X      k++;
X    }
X
X#ifdef	DEBUG
X  print_derives();
X#endif
X}
X
Xfree_derives()
X{
X  FREE(derives[start_symbol]);
X  FREE(derives);
X}
X
X#ifdef	DEBUG
Xprint_derives()
X{
X  register int i;
X  register short *sp;
X
X  printf("\nDERIVES\n\n");
X
X  for (i = start_symbol; i < nsyms; i++)
X    {
X      printf("%s derives ", symbol_name[i]);
X      for (sp = derives[i]; *sp >= 0; sp++)
X	{
X	  printf("  %d", *sp);
X	}
X      putchar('\n');
X    }
X
X  putchar('\n');
X}
X#endif
X
X
Xset_nullable()
X{
X    register int i, j;
X    register int empty;
X    int done;
X
X    nullable = MALLOC(nsyms);
X    if (nullable == 0) no_space();
X
X    for (i = 0; i < nsyms; ++i)
X	nullable[i] = 0;
X
X    done = 0;
X    while (!done)
X    {
X	done = 1;
X	for (i = 1; i < nitems; i++)
X	{
X	    empty = 1;
X	    while ((j = ritem[i]) >= 0)
X	    {
X		if (!nullable[j])
X		    empty = 0;
X		++i;
X	    }
X	    if (empty)
X	    {
X		j = rlhs[-j];
X		if (!nullable[j])
X		{
X		    nullable[j] = 1;
X		    done = 0;
X		}
X	    }
X	}
X    }
X
X#ifdef DEBUG
X    for (i = 0; i < nsyms; i++)
X    {
X	if (nullable[i])
X	    printf("%s is nullable\n", symbol_name[i]);
X	else
X	    printf("%s is not nullable\n", symbol_name[i]);
X    }
X#endif
X}
X
X
Xfree_nullable()
X{
X  FREE(nullable);
X}
X
X
Xlr0()
X{
X    set_derives();
X    set_nullable();
X    generate_states();
X}
END_OF_FILE
if [[ 9615 -ne `wc -c <'lr0.c'` ]]; then
    echo shar: \"'lr0.c'\" unpacked with wrong size!
fi
# end of 'lr0.c'
fi
if test -f 'mkpar.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'mkpar.c'\"
else
echo shar: Extracting \"'mkpar.c'\" \(6766 characters\)
sed "s/^X//" >'mkpar.c' <<'END_OF_FILE'
X#include "defs.h"
X
Xaction **parser;
Xint SRtotal;
Xint RRtotal;
Xshort *SRconflicts;
Xshort *RRconflicts;
Xshort *defred;
Xshort *rules_used;
Xshort nunused;
Xshort final_state;
X
Xstatic int SRcount;
Xstatic int RRcount;
X
Xextern action *parse_actions();
Xextern action *get_shifts();
Xextern action *add_reductions();
Xextern action *add_reduce();
X
X
Xmake_parser()
X{
X    register int i;
X
X    parser = NEW2(nstates, action *);
X    for (i = 0; i < nstates; i++)
X	parser[i] = parse_actions(i);
X
X    find_final_state();
X    remove_conflicts();
X    unused_rules();
X    if (SRtotal + RRtotal > 0) total_conflicts();
X    defreds();
X}
X
X
Xaction *
Xparse_actions(stateno)
Xregister int stateno;
X{
X    register action *actions;
X
X    actions = get_shifts(stateno);
X    actions = add_reductions(stateno, actions);
X    return (actions);
X}
X
X
Xaction *
Xget_shifts(stateno)
Xint stateno;
X{
X    register action *actions, *temp;
X    register shifts *sp;
X    register short *to_state;
X    register int i, k;
X    register int symbol;
X
X    actions = 0;
X    sp = shift_table[stateno];
X    if (sp)
X    {
X	to_state = sp->shift;
X	for (i = sp->nshifts - 1; i >= 0; i--)
X	{
X	    k = to_state[i];
X	    symbol = accessing_symbol[k];
X	    if (ISTOKEN(symbol))
X	    {
X		temp = NEW(action);
X		temp->next = actions;
X		temp->symbol = symbol;
X		temp->number = k;
X		temp->prec = symbol_prec[symbol];
X		temp->action_code = SHIFT;
X		temp->assoc = symbol_assoc[symbol];
X		actions = temp;
X	    }
X	}
X    }
X    return (actions);
X}
X
Xaction *
Xadd_reductions(stateno, actions)
Xint stateno;
Xregister action *actions;
X{
X    register int i, j, m, n;
X    register int ruleno, tokensetsize;
X    register unsigned *rowp;
X
X    tokensetsize = WORDSIZE(ntokens);
X    m = lookaheads[stateno];
X    n = lookaheads[stateno + 1];
X    for (i = m; i < n; i++)
X    {
X	ruleno = LAruleno[i];
X	rowp = LA + i * tokensetsize;
X	for (j = ntokens - 1; j >= 0; j--)
X	{
X	    if (BIT(rowp, j))
X		actions = add_reduce(actions, ruleno, j);
X	}
X    }
X    return (actions);
X}
X
X
Xaction *
Xadd_reduce(actions, ruleno, symbol)
Xregister action *actions;
Xregister int ruleno, symbol;
X{
X    register action *temp, *prev, *next;
X
X    prev = 0;
X    for (next = actions; next && next->symbol < symbol; next = next->next)
X	prev = next;
X
X    while (next && next->symbol == symbol && next->action_code == SHIFT)
X    {
X	prev = next;
X	next = next->next;
X    }
X
X    while (next && next->symbol == symbol &&
X	    next->action_code == REDUCE && next->number < ruleno)
X    {
X	prev = next;
X	next = next->next;
X    }
X
X    temp = NEW(action);
X    temp->next = next;
X    temp->symbol = symbol;
X    temp->number = ruleno;
X    temp->prec = rprec[ruleno];
X    temp->action_code = REDUCE;
X    temp->assoc = rassoc[ruleno];
X
X    if (prev)
X	prev->next = temp;
X    else
X	actions = temp;
X
X    return (actions);
X}
X
X
Xfind_final_state()
X{
X    register int goal, i;
X    register short *to_state;
X    register shifts *p;
X
X    p = shift_table[0];
X    to_state = p->shift;
X    goal = ritem[1];
X    for (i = p->nshifts - 1; i >= 0; --i)
X    {
X	final_state = to_state[i];
X	if (accessing_symbol[final_state] == goal) break;
X    }
X}
X
X
Xunused_rules()
X{
X    register int i;
X    register action *p;
X
X    rules_used = (short *) MALLOC(nrules*sizeof(short));
X    if (rules_used == 0) no_space();
X
X    for (i = 0; i < nrules; ++i)
X	rules_used[i] = 0;
X
X    for (i = 0; i < nstates; ++i)
X    {
X	for (p = parser[i]; p; p = p->next)
X	{
X	    if (p->action_code == REDUCE && p->suppressed == 0)
X		rules_used[p->number] = 1;
X	}
X    }
X
X    nunused = 0;
X    for (i = 3; i < nrules; ++i)
X	if (!rules_used[i]) ++nunused;
X
X    if (nunused)
X	if (nunused == 1)
X	    fprintf(stderr, "%s: 1 rule never reduced\n", myname);
X	else
X	    fprintf(stderr, "%s: %d rules never reduced\n", myname, nunused);
X}
X
X
Xremove_conflicts()
X{
X    register int i;
X    register int symbol;
X    register action *p, *q;
X
X    SRtotal = 0;
X    RRtotal = 0;
X    SRconflicts = NEW2(nstates, short);
X    RRconflicts = NEW2(nstates, short);
X    for (i = 0; i < nstates; i++)
X    {
X	SRcount = 0;
X	RRcount = 0;
X	for (p = parser[i]; p; p = q->next)
X	{
X	    symbol = p->symbol;
X	    q = p;
X	    while (q->next && q->next->symbol == symbol)
X		q = q->next;
X	    if (i == final_state && symbol == 0)
X		end_conflicts(p, q);
X	    else if (p != q)
X		resolve_conflicts(p, q);
X	}
X	SRtotal += SRcount;
X	RRtotal += RRcount;
X	SRconflicts[i] = SRcount;
X	RRconflicts[i] = RRcount;
X    }
X}
X
X
Xend_conflicts(p, q)
Xregister action *p, *q;
X{
X    for (;;)
X    {
X	SRcount++;
X	p->suppressed = 1;
X	if (p == q) break;
X	p = p->next;
X    }
X}
X
X
Xresolve_conflicts(first, last)
Xregister action *first, *last;
X{
X    register action *p;
X    register int count;
X
X    count = 1;
X    for (p = first; p != last; p = p->next)
X 	++count;
X    assert(count > 1);
X
X    if (first->action_code == SHIFT && count == 2 &&
X	    first->prec > 0 && last->prec > 0)
X    {
X	if (first->prec == last->prec)
X	{
X	    if (first->assoc == LEFT)
X		first->suppressed = 2;
X	    else if (first->assoc == RIGHT)
X		last->suppressed = 2;
X	    else
X	    {
X		first->suppressed = 2;
X		last->suppressed = 2;
X		first->action_code = ERROR;
X		last->action_code = ERROR;
X	    }
X	}
X	else if (first->prec < last->prec)
X	    first->suppressed = 2;
X	else
X	    last->suppressed = 2;
X    }
X    else
X    {
X	if (first->action_code == SHIFT)
X	    SRcount += (count - 1);
X        else
X	    RRcount += (count - 1);
X	for (p = first; p != last; p = p->next, p->suppressed = 1)
X	    continue;
X    }
X}
X
X
Xtotal_conflicts()
X{
X    fprintf(stderr, "%s: ", myname);
X    if (SRtotal == 1)
X	fprintf(stderr, "1 shift/reduce conflict");
X    else if (SRtotal > 1)
X	fprintf(stderr, "%d shift/reduce conflicts", SRtotal);
X
X    if (SRtotal && RRtotal)
X	fprintf(stderr, ", ");
X
X    if (RRtotal == 1)
X	fprintf(stderr, "1 reduce/reduce conflict");
X    else if (RRtotal > 1)
X	fprintf(stderr, "%d reduce/reduce conflicts", RRtotal);
X
X    fprintf(stderr, ".\n");
X}
X
X
Xint
Xsole_reduction(stateno)
Xint stateno;
X{
X    register int count, ruleno;
X    register action *p;
X
X    count = 0;
X    ruleno = 0; 
X    for (p = parser[stateno]; p; p = p->next)
X    {
X	if (p->action_code == SHIFT && p->suppressed == 0)
X	    return (0);
X	else if (p->action_code == REDUCE && p->suppressed == 0)
X	{
X	    if (ruleno > 0 && p->number != ruleno)
X		return (0);
X	    if (p->symbol != 1)
X		++count;
X	    ruleno = p->number;
X	}
X    }
X
X    if (count == 0)
X	return (0);
X    return (ruleno);
X}
X
X
Xdefreds()
X{
X    register int i;
X
X    defred = NEW2(nstates, short);
X    for (i = 0; i < nstates; i++)
X	defred[i] = sole_reduction(i);
X}
X 
Xfree_action_row(p)
Xregister action *p;
X{
X  register action *q;
X
X  while (p)
X    {
X      q = p->next;
X      FREE(p);
X      p = q;
X    }
X}
X
Xfree_parser()
X{
X  register int i;
X
X  for (i = 0; i < nstates; i++)
X    free_action_row(parser[i]);
X
X  FREE(parser);
X}
END_OF_FILE
if [[ 6766 -ne `wc -c <'mkpar.c'` ]]; then
    echo shar: \"'mkpar.c'\" unpacked with wrong size!
fi
# end of 'mkpar.c'
fi
if test -f 'skeleton.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'skeleton.c'\"
else
echo shar: Extracting \"'skeleton.c'\" \(7465 characters\)
sed "s/^X//" >'skeleton.c' <<'END_OF_FILE'
X#include "defs.h"
X
X/*  The three line banner used here should be replaced with a one line	*/
X/*  #ident directive if the target C compiler supports #ident		*/
X/*  directives.								*/
X/*									*/
X/*  If the skeleton is changed, the banner should be changed so that	*/
X/*  the altered version can easily be distinguished from the original.	*/
X
Xchar *banner[] =
X{
X    "#ifndef lint",
X    "char yysccsid[] = \"@(#)yaccpar	1.4 (Berkeley) 02/25/90\";",
X    "#endif",
X    0
X};
X
X
Xchar *header[] =
X{
X    "#define yyclearin (yychar=(-1))",
X    "#define yyerrok (yyerrflag=0)",
X    "#ifndef YYSTACKSIZE",
X    "#ifdef YYMAXDEPTH",
X    "#define YYSTACKSIZE YYMAXDEPTH",
X    "#else",
X    "#define YYSTACKSIZE 300",
X    "#endif",
X    "#endif",
X    "int yydebug;",
X    "int yynerrs;",
X    "int yyerrflag;",
X    "int yychar;",
X    "short *yyssp;",
X    "YYSTYPE *yyvsp;",
X    "YYSTYPE yyval;",
X    "YYSTYPE yylval;",
X    "#define yystacksize YYSTACKSIZE",
X    "short yyss[YYSTACKSIZE];",
X    "YYSTYPE yyvs[YYSTACKSIZE];",
X    0
X};
X
X
Xchar *body[] =
X{
X    "#define YYABORT goto yyabort",
X    "#define YYACCEPT goto yyaccept",
X    "#define YYERROR goto yyerrlab",
X    "int",
X    "yyparse()",
X    "{",
X    "    register int yym, yyn, yystate;",
X    "#if YYDEBUG",
X    "    register char *yys;",
X    "    extern char *getenv();",
X    "",
X    "    if (yys = getenv(\"YYDEBUG\"))",
X    "    {",
X    "        yyn = *yys;",
X    "        if (yyn >= '0' && yyn <= '9')",
X    "            yydebug = yyn - '0';",
X    "    }",
X    "#endif",
X    "",
X    "    yynerrs = 0;",
X    "    yyerrflag = 0;",
X    "    yychar = (-1);",
X    "",
X    "    yyssp = yyss;",
X    "    yyvsp = yyvs;",
X    "    *yyssp = yystate = 0;",
X    "",
X    "yyloop:",
X    "    if (yyn = yydefred[yystate]) goto yyreduce;",
X    "    if (yychar < 0)",
X    "    {",
X    "        if ((yychar = yylex()) < 0) yychar = 0;",
X    "#if YYDEBUG",
X    "        if (yydebug)",
X    "        {",
X    "            yys = 0;",
X    "            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];",
X    "            if (!yys) yys = \"illegal-symbol\";",
X    "            printf(\"yydebug: state %d, reading %d (%s)\\n\", yystate,",
X    "                    yychar, yys);",
X    "        }",
X    "#endif",
X    "    }",
X    "    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&",
X    "            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)",
X    "    {",
X    "#if YYDEBUG",
X    "        if (yydebug)",
X    "            printf(\"yydebug: state %d, shifting to state %d\\n\",",
X    "                    yystate, yytable[yyn]);",
X    "#endif",
X    "        if (yyssp >= yyss + yystacksize - 1)",
X    "        {",
X    "            goto yyoverflow;",
X    "        }",
X    "        *++yyssp = yystate = yytable[yyn];",
X    "        *++yyvsp = yylval;",
X    "        yychar = (-1);",
X    "        if (yyerrflag > 0)  --yyerrflag;",
X    "        goto yyloop;",
X    "    }",
X    "    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&",
X    "            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)",
X    "    {",
X    "        yyn = yytable[yyn];",
X    "        goto yyreduce;",
X    "    }",
X    "    if (yyerrflag) goto yyinrecovery;",
X    "#ifdef lint",
X    "    goto yynewerror;",
X    "#endif",
X    "yynewerror:",
X    "    yyerror(\"syntax error\");",
X    "#ifdef lint",
X    "    goto yyerrlab;",
X    "#endif",
X    "yyerrlab:",
X    "    ++yynerrs;",
X    "yyinrecovery:",
X    "    if (yyerrflag < 3)",
X    "    {",
X    "        yyerrflag = 3;",
X    "        for (;;)",
X    "        {",
X    "            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&",
X    "                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)",
X    "            {",
X    "#if YYDEBUG",
X    "                if (yydebug)",
X    "                    printf(\"yydebug: state %d, error recovery shifting\\",
X    " to state %d\\n\", *yyssp, yytable[yyn]);",
X    "#endif",
X    "                if (yyssp >= yyss + yystacksize - 1)",
X    "                {",
X    "                    goto yyoverflow;",
X    "                }",
X    "                *++yyssp = yystate = yytable[yyn];",
X    "                *++yyvsp = yylval;",
X    "                goto yyloop;",
X    "            }",
X    "            else",
X    "            {",
X    "#if YYDEBUG",
X    "                if (yydebug)",
X    "                    printf(\"yydebug: error recovery discarding state %d\
X\\n\",",
X    "                            *yyssp);",
X    "#endif",
X    "                if (yyssp <= yyss) goto yyabort;",
X    "                --yyssp;",
X    "                --yyvsp;",
X    "            }",
X    "        }",
X    "    }",
X    "    else",
X    "    {",
X    "        if (yychar == 0) goto yyabort;",
X    "#if YYDEBUG",
X    "        if (yydebug)",
X    "        {",
X    "            yys = 0;",
X    "            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];",
X    "            if (!yys) yys = \"illegal-symbol\";",
X    "            printf(\"yydebug: state %d, error recovery discards token %d\
X (%s)\\n\",",
X    "                    yystate, yychar, yys);",
X    "        }",
X    "#endif",
X    "        yychar = (-1);",
X    "        goto yyloop;",
X    "    }",
X    "yyreduce:",
X    "#if YYDEBUG",
X    "    if (yydebug)",
X    "        printf(\"yydebug: state %d, reducing by rule %d (%s)\\n\",",
X    "                yystate, yyn, yyrule[yyn]);",
X    "#endif",
X    "    yym = yylen[yyn];",
X    "    yyval = yyvsp[1-yym];",
X    "    switch (yyn)",
X    "    {",
X    0
X};
X
X
Xchar *trailer[] =
X{
X    "    }",
X    "    yyssp -= yym;",
X    "    yystate = *yyssp;",
X    "    yyvsp -= yym;",
X    "    yym = yylhs[yyn];",
X    "    if (yystate == 0 && yym == 0)",
X    "    {",
X    "#ifdef YYDEBUG",
X    "        if (yydebug)",
X    "            printf(\"yydebug: after reduction, shifting from state 0 to\\",
X    " state %d\\n\", YYFINAL);",
X    "#endif",
X    "        yystate = YYFINAL;",
X    "        *++yyssp = YYFINAL;",
X    "        *++yyvsp = yyval;",
X    "        if (yychar < 0)",
X    "        {",
X    "            if ((yychar = yylex()) < 0) yychar = 0;",
X    "#if YYDEBUG",
X    "            if (yydebug)",
X    "            {",
X    "                yys = 0;",
X    "                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];",
X    "                if (!yys) yys = \"illegal-symbol\";",
X    "                printf(\"yydebug: state %d, reading %d (%s)\\n\",",
X    "                        YYFINAL, yychar, yys);",
X    "            }",
X    "#endif",
X    "        }",
X    "        if (yychar == 0) goto yyaccept;",
X    "        goto yyloop;",
X    "    }",
X    "    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&",
X    "            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)",
X    "        yystate = yytable[yyn];",
X    "    else",
X    "        yystate = yydgoto[yym];",
X    "#ifdef YYDEBUG",
X    "    if (yydebug)",
X    "        printf(\"yydebug: after reduction, shifting from state %d \\",
X    "to state %d\\n\", *yyssp, yystate);",
X    "#endif",
X    "    if (yyssp >= yyss + yystacksize - 1)",
X    "    {",
X    "        goto yyoverflow;",
X    "    }",
X    "    *++yyssp = yystate;",
X    "    *++yyvsp = yyval;",
X    "    goto yyloop;",
X    "yyoverflow:",
X    "    yyerror(\"yacc stack overflow\");",
X    "yyabort:",
X    "    return (1);",
X    "yyaccept:",
X    "    return (0);",
X    "}",
X    0
X};
X
X
Xwrite_section(section)
Xchar *section[];
X{
X    register int i;
X
X    for (i = 0; section[i]; ++i)
X    {
X	++outline;
X	fprintf(output_file, "%s\n", section[i]);
X    }
X}
END_OF_FILE
if [[ 7465 -ne `wc -c <'skeleton.c'` ]]; then
    echo shar: \"'skeleton.c'\" unpacked with wrong size!
fi
# end of 'skeleton.c'
fi
echo shar: End of archive 2 \(of 5\).
cp /dev/null ark2isdone
MISSING=""
for I in 1 2 3 4 5 ; do
    if test ! -f ark${I}isdone ; then
	MISSING="${MISSING} ${I}"
    fi
done
if test "${MISSING}" = "" ; then
    echo You have unpacked all 5 archives.
    rm -f ark[1-9]isdone
else
    echo You still need to unpack the following archives:
    echo "        " ${MISSING}
fi
##  End of shell archive.
exit 0
