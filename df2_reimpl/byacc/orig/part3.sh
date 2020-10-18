#! /bin/sh
# This is a shell archive.  Remove anything before this line, then unpack
# it by saving it into a file and typing "sh file".  To overwrite existing
# files, type "sh file -c".  You can also feed this as standard input via
# unshar, or by typing "sh <file", e.g..  If this archive is complete, you
# will see the following message at the end:
#		"End of archive 3 (of 5)."
# Contents:  output.c test/ftp.output
# Wrapped by rsalz@litchi.bbn.com on Mon Apr  2 11:43:43 1990
PATH=/bin:/usr/bin:/usr/ucb ; export PATH
if test -f 'output.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'output.c'\"
else
echo shar: Extracting \"'output.c'\" \(20075 characters\)
sed "s/^X//" >'output.c' <<'END_OF_FILE'
X#include "defs.h"
X
Xstatic int nvectors;
Xstatic int nentries;
Xstatic short **froms;
Xstatic short **tos;
Xstatic short *tally;
Xstatic short *width;
Xstatic short *state_count;
Xstatic short *order;
Xstatic short *base;
Xstatic short *pos;
Xstatic int maxtable;
Xstatic short *table;
Xstatic short *check;
Xstatic int lowzero;
Xstatic int high;
X
X
Xoutput()
X{
X    free_itemsets();
X    free_shifts();
X    free_reductions();
X    output_stored_text();
X    output_defines();
X    output_rule_data();
X    output_yydefred();
X    output_actions();
X    free_parser();
X    output_debug();
X    output_stype();
X    write_section(header);
X    output_trailing_text();
X    write_section(body);
X    output_semantic_actions();
X    write_section(trailer);
X}
X
X
Xoutput_rule_data()
X{
X    register int i;
X    register int j;
X
X  
X    fprintf(output_file, "short yylhs[] = {%42d,",
X	    symbol_value[start_symbol]);
X
X    j = 10;
X    for (i = 3; i < nrules; i++)
X    {
X	if (j >= 10)
X	{
X	    ++outline;
X	    putc('\n', output_file);
X	    j = 1;
X	}
X        else
X	    ++j;
X
X        fprintf(output_file, "%5d,", symbol_value[rlhs[i]]);
X    }
X    outline += 2;
X    fprintf(output_file, "\n};\n");
X
X    fprintf(output_file, "short yylen[] = {%42d,", 2);
X
X    j = 10;
X    for (i = 3; i < nrules; i++)
X    {
X	if (j >= 10)
X	{
X	    ++outline;
X	    putc('\n', output_file);
X	    j = 1;
X	}
X	else
X	  j++;
X
X        fprintf(output_file, "%5d,", rrhs[i + 1] - rrhs[i] - 1);
X    }
X    outline += 2;
X    fprintf(output_file, "\n};\n");
X}
X
X
Xoutput_yydefred()
X{
X    register int i, j;
X
X    fprintf(output_file, "short yydefred[] = {%39d,",
X	    (defred[0] ? defred[0] - 2 : 0));
X
X    j = 10;
X    for (i = 1; i < nstates; i++)
X    {
X	if (j < 10)
X	    ++j;
X	else
X	{
X	    ++outline;
X	    putc('\n', output_file);
X	    j = 1;
X	}
X
X	fprintf(output_file, "%5d,", (defred[i] ? defred[i] - 2 : 0));
X    }
X
X    outline += 2;
X    fprintf(output_file, "\n};\n");
X}
X
X
Xoutput_actions()
X{
X    nvectors = 2*nstates + nvars;
X
X    froms = NEW2(nvectors, short *);
X    tos = NEW2(nvectors, short *);
X    tally = NEW2(nvectors, short);
X    width = NEW2(nvectors, short);
X
X    token_actions();
X    FREE(lookaheads);
X    FREE(LA);
X    FREE(LAruleno);
X    FREE(accessing_symbol);
X
X    goto_actions();
X    FREE(goto_map + ntokens);
X    FREE(from_state);
X    FREE(to_state);
X
X    sort_actions();
X    pack_table();
X    output_base();
X    output_table();
X    output_check();
X}
X
X
Xtoken_actions()
X{
X    register int i, j;
X    register int shiftcount, reducecount;
X    register int max, min;
X    register short *actionrow, *r, *s;
X    register action *p;
X
X    actionrow = NEW2(2*ntokens, short);
X    for (i = 0; i < nstates; ++i)
X    {
X	if (parser[i])
X	{
X	    for (j = 0; j < 2*ntokens; ++j)
X	    actionrow[j] = 0;
X
X	    shiftcount = 0;
X	    reducecount = 0;
X	    for (p = parser[i]; p; p = p->next)
X	    {
X		if (p->suppressed == 0)
X		{
X		    if (p->action_code == SHIFT)
X		    {
X			++shiftcount;
X			actionrow[p->symbol] = p->number;
X		    }
X		    else if (p->action_code == REDUCE && p->number != defred[i])
X		    {
X			++reducecount;
X			actionrow[p->symbol + ntokens] = p->number;
X		    }
X		}
X	    }
X
X	    tally[i] = shiftcount;
X	    tally[nstates+i] = reducecount;
X	    width[i] = 0;
X	    width[nstates+i] = 0;
X	    if (shiftcount > 0)
X	    {
X		froms[i] = r = NEW2(shiftcount, short);
X		tos[i] = s = NEW2(shiftcount, short);
X		min = MAXSHORT;
X		max = 0;
X		for (j = 0; j < ntokens; ++j)
X		{
X		    if (actionrow[j])
X		    {
X			if (min > symbol_value[j])
X			    min = symbol_value[j];
X			if (max < symbol_value[j])
X			    max = symbol_value[j];
X			*r++ = symbol_value[j];
X			*s++ = actionrow[j];
X		    }
X		}
X		width[i] = max - min + 1;
X	    }
X	    if (reducecount > 0)
X	    {
X		froms[nstates+i] = r = NEW2(reducecount, short);
X		tos[nstates+i] = s = NEW2(reducecount, short);
X		min = MAXSHORT;
X		max = 0;
X		for (j = 0; j < ntokens; ++j)
X		{
X		    if (actionrow[ntokens+j])
X		    {
X			if (min > symbol_value[j])
X			    min = symbol_value[j];
X			if (max < symbol_value[j])
X			    max = symbol_value[j];
X			*r++ = symbol_value[j];
X			*s++ = actionrow[ntokens+j] - 2;
X		    }
X		}
X		width[nstates+i] = max - min + 1;
X	    }
X	}
X    }
X    FREE(actionrow);
X}
X
Xgoto_actions()
X{
X    register int i, j, k;
X
X    state_count = NEW2(nstates, short);
X
X    k = default_goto(start_symbol + 1);
X    fprintf(output_file, "short yydgoto[] = {%40d,", k);
X    save_column(start_symbol + 1, k);
X
X    j = 10;
X    for (i = start_symbol + 2; i < nsyms; i++)
X    {
X	if (j >= 10)
X	{
X	    ++outline;
X	    putc('\n', output_file);
X	    j = 1;
X	}
X	else
X	    ++j;
X
X	k = default_goto(i);
X	fprintf(output_file, "%5d,", k);
X	save_column(i, k);
X    }
X
X    outline += 2;
X    fprintf(output_file, "\n};\n");
X    FREE(state_count);
X}
X
Xint
Xdefault_goto(symbol)
Xint symbol;
X{
X    register int i;
X    register int m;
X    register int n;
X    register int default_state;
X    register int max;
X
X    m = goto_map[symbol];
X    n = goto_map[symbol + 1];
X
X    if (m == n) return (0);
X
X    for (i = 0; i < nstates; i++)
X	state_count[i] = 0;
X
X    for (i = m; i < n; i++)
X	state_count[to_state[i]]++;
X
X    max = 0;
X    default_state = 0;
X    for (i = 0; i < nstates; i++)
X    {
X	if (state_count[i] > max)
X	{
X	    max = state_count[i];
X	    default_state = i;
X	}
X    }
X
X    return (default_state);
X}
X
X
X
Xsave_column(symbol, default_state)
Xint symbol;
Xint default_state;
X{
X    register int i;
X    register int m;
X    register int n;
X    register short *sp;
X    register short *sp1;
X    register short *sp2;
X    register int count;
X    register int symno;
X
X    m = goto_map[symbol];
X    n = goto_map[symbol + 1];
X
X    count = 0;
X    for (i = m; i < n; i++)
X    {
X	if (to_state[i] != default_state)
X	    ++count;
X    }
X    if (count == 0) return;
X
X    symno = symbol_value[symbol] + 2*nstates;
X
X    froms[symno] = sp1 = sp = NEW2(count, short);
X    tos[symno] = sp2 = NEW2(count, short);
X
X    for (i = m; i < n; i++)
X    {
X	if (to_state[i] != default_state)
X	{
X	    *sp1++ = from_state[i];
X	    *sp2++ = to_state[i];
X	}
X    }
X
X    tally[symno] = count;
X    width[symno] = sp1[-1] - sp[0] + 1;
X}
X
Xsort_actions()
X{
X  register int i;
X  register int j;
X  register int k;
X  register int t;
X  register int w;
X
X  order = NEW2(nvectors, short);
X  nentries = 0;
X
X  for (i = 0; i < nvectors; i++)
X    {
X      if (tally[i] > 0)
X	{
X	  t = tally[i];
X	  w = width[i];
X	  j = nentries - 1;
X
X	  while (j >= 0 && (width[order[j]] < w))
X	    j--;
X
X	  while (j >= 0 && (width[order[j]] == w) && (tally[order[j]] < t))
X	    j--;
X
X	  for (k = nentries - 1; k > j; k--)
X	    order[k + 1] = order[k];
X
X	  order[j + 1] = i;
X	  nentries++;
X	}
X    }
X}
X
X
Xpack_table()
X{
X    register int i;
X    register int place;
X    register int state;
X
X    base = NEW2(nvectors, short);
X    pos = NEW2(nentries, short);
X
X    maxtable = 1000;
X    table = NEW2(maxtable, short);
X    check = NEW2(maxtable, short);
X
X    lowzero = 0;
X    high = 0;
X
X    for (i = 0; i < maxtable; i++)
X	check[i] = -1;
X
X    for (i = 0; i < nentries; i++)
X    {
X	state = matching_vector(i);
X
X	if (state < 0)
X	    place = pack_vector(i);
X	else
X	    place = base[state];
X
X	pos[i] = place;
X	base[order[i]] = place;
X    }
X
X    for (i = 0; i < nvectors; i++)
X    {
X	if (froms[i])
X	    FREE(froms[i]);
X	if (tos[i])
X	    FREE(tos[i]);
X    }
X
X    FREE(froms);
X    FREE(tos);
X    FREE(pos);
X}
X
X
X/*  The function matching_vector determines if the vector specified by	*/
X/*  the input parameter matches a previously considered	vector.  The	*/
X/*  test at the start of the function checks if the vector represents	*/
X/*  a row of shifts over terminal symbols or a row of reductions, or a	*/
X/*  column of shifts over a nonterminal symbol.  Berkeley Yacc does not	*/
X/*  check if a column of shifts over a nonterminal symbols matches a	*/
X/*  previously considered vector.  Because of the nature of LR parsing	*/
X/*  tables, no two columns can match.  Therefore, the only possible	*/
X/*  match would be between a row and a column.  Such matches are	*/
X/*  unlikely.  Therefore, to save time, no attempt is made to see if a	*/
X/*  column matches a previously considered vector.			*/
X/*									*/
X/*  Matching_vector is poorly designed.  The test could easily be made	*/
X/*  faster.  Also, it depends on the vectors being in a specific	*/
X/*  order.								*/
X
Xint
Xmatching_vector(vector)
Xint vector;
X{
X    register int i;
X    register int j;
X    register int k;
X    register int t;
X    register int w;
X    register int match;
X    register int prev;
X
X    i = order[vector];
X    if (i >= 2*nstates)
X	return (-1);
X
X    t = tally[i];
X    w = width[i];
X
X    for (prev = vector - 1; prev >= 0; prev--)
X    {
X	j = order[prev];
X	if (width[j] != w || tally[j] != t)
X	    return (-1);
X
X	match = 1;
X	for (k = 0; match && k < t; k++)
X	{
X	    if (tos[j][k] != tos[i][k] || froms[j][k] != froms[i][k])
X		match = 0;
X	}
X
X	if (match)
X	    return (j);
X    }
X
X    return (-1);
X}
X
X
X
Xint
Xpack_vector(vector)
Xint vector;
X{
X    register int i, j, k, l;
X    register int t;
X    register int loc;
X    register int ok;
X    register short *from;
X    register short *to;
X    int newmax;
X
X    i = order[vector];
X    t = tally[i];
X    assert(t);
X
X    from = froms[i];
X    to = tos[i];
X
X    j = lowzero - from[0];
X    for (k = 1; k < t; ++k)
X	if (lowzero - from[k] > j)
X	    j = lowzero - from[k];
X    for (;; ++j)
X    {
X	if (j == 0)
X	    continue;
X	ok = 1;
X	for (k = 0; ok && k < t; k++)
X	{
X	    loc = j + from[k];
X	    if (loc >= maxtable)
X	    {
X		if (loc >= MAXTABLE)
X		    fatal("maximum table size exceeded");
X
X		newmax = maxtable;
X		do { newmax += 200; } while (newmax <= loc);
X		table = (short *) realloc(table, newmax*sizeof(short));
X		if (table == 0) no_space();
X		check = (short *) realloc(check, newmax*sizeof(short));
X		if (check == 0) no_space();
X		for (l  = maxtable; l < newmax; ++l)
X		{
X		    table[l] = 0;
X		    check[l] = -1;
X		}
X		maxtable = newmax;
X	    }
X
X	    if (check[loc] != -1)
X		ok = 0;
X	}
X	for (k = 0; ok && k < vector; k++)
X	{
X	    if (pos[k] == j)
X		ok = 0;
X	}
X	if (ok)
X	{
X	    for (k = 0; k < t; k++)
X	    {
X		loc = j + from[k];
X		table[loc] = to[k];
X		check[loc] = from[k];
X		if (loc > high) high = loc;
X	    }
X
X	    while (check[lowzero] != -1)
X		++lowzero;
X
X	    return (j);
X	}
X    }
X}
X
X
X
Xoutput_base()
X{
X    register int i, j;
X
X    fprintf(output_file, "short yysindex[] = {%39d,", base[0]);
X
X    j = 10;
X    for (i = 1; i < nstates; i++)
X    {
X	if (j >= 10)
X	{
X	    ++outline;
X	    putc('\n', output_file);
X	    j = 1;
X	}
X	else
X	    ++j;
X
X	fprintf(output_file, "%5d,", base[i]);
X    }
X
X    outline += 2;
X    fprintf(output_file, "\n};\nshort yyrindex[] = {%39d,",
X	    base[nstates]);
X
X    j = 10;
X    for (i = nstates + 1; i < 2*nstates; i++)
X    {
X	if (j >= 10)
X	{
X	    ++outline;
X	    putc('\n', output_file);
X	    j = 1;
X	}
X	else
X	    ++j;
X
X	fprintf(output_file, "%5d,", base[i]);
X    }
X
X    outline += 2;
X    fprintf(output_file, "\n};\nshort yygindex[] = {%39d,",
X	    base[2*nstates]);
X
X    j = 10;
X    for (i = 2*nstates + 1; i < nvectors - 1; i++)
X    {
X	if (j >= 10)
X	{
X	    ++outline;
X	    putc('\n', output_file);
X	    j = 1;
X	}
X	else
X	    ++j;
X
X	fprintf(output_file, "%5d,", base[i]);
X    }
X
X    outline += 2;
X    fprintf(output_file, "\n};\n");
X    FREE(base);
X}
X
X
X
Xoutput_table()
X{
X    register int i;
X    register int j;
X
X    ++outline;
X    fprintf(output_file, "#define YYTABLESIZE %d\n", high);
X    fprintf(output_file, "short yytable[] = {%40d,", table[0]);
X
X    j = 10;
X    for (i = 1; i <= high; i++)
X    {
X	if (j >= 10)
X	{
X	    ++outline;
X	    putc('\n', output_file);
X	    j = 1;
X	}
X	else
X	    ++j;
X
X	fprintf(output_file, "%5d,", table[i]);
X    }
X
X    outline += 2;
X    fprintf(output_file, "\n};\n");
X    FREE(table);
X}
X
X
X
Xoutput_check()
X{
X    register int i;
X    register int j;
X
X    fprintf(output_file, "short yycheck[] = {%40d,", check[0]);
X
X    j = 10;
X    for (i = 1; i <= high; i++)
X    {
X	if (j >= 10)
X	{
X	    ++outline;
X	    putc('\n', output_file);
X	    j = 1;
X	}
X	else
X	    ++j;
X
X	fprintf(output_file, "%5d,", check[i]);
X    }
X
X    outline += 2;
X    fprintf(output_file, "\n};\n");
X    FREE(check);
X}
X
X
Xint
Xis_C_identifier(name)
Xchar *name;
X{
X    register char *s;
X    register int c;
X
X    s = name;
X    c = *s;
X    if (c == '"')
X    {
X	c = *++s;
X	if (!isalpha(c) && c != '_' && c != '$')
X	    return (0);
X	while ((c = *++s) != '"')
X	{
X	    if (!isalnum(c) && c != '_' && c != '$')
X		return (0);
X	}
X	return (1);
X    }
X
X    if (!isalpha(c) && c != '_' && c != '$')
X	return (0);
X    while (c = *++s)
X    {
X	if (!isalnum(c) && c != '_' && c != '$')
X	    return (0);
X    }
X    return (1);
X}
X
X
Xoutput_defines()
X{
X    register int c, i;
X    register char *s;
X
X    for (i = 2; i < ntokens; ++i)
X    {
X	s = symbol_name[i];
X	if (is_C_identifier(s))
X	{
X	    fprintf(output_file, "#define ");
X	    if (dflag) fprintf(defines_file, "#define ");
X	    c = *s;
X	    if (c == '"')
X	    {
X		while ((c = *++s) != '"')
X		{
X		    putc(c, output_file);
X		    if (dflag) putc(c, defines_file);
X		}
X	    }
X	    else
X	    {
X		do
X		{
X		    putc(c, output_file);
X		    if (dflag) putc(c, defines_file);
X		}
X		while (c = *++s);
X	    }
X	    ++outline;
X	    fprintf(output_file, " %d\n", symbol_value[i]);
X	    if (dflag) fprintf(defines_file, " %d\n", symbol_value[i]);
X	}
X    }
X
X    ++outline;
X    fprintf(output_file, "#define YYERRCODE %d\n", symbol_value[1]);
X
X    if (dflag && unionized)
X    {
X	fclose(union_file);
X	union_file = fopen(union_file_name, "r");
X	if (union_file == NULL) open_error(union_file_name);
X	while ((c = getc(union_file)) != EOF)
X	    putc(c, defines_file);
X	fprintf(defines_file, " YYSTYPE;\nextern YYSTYPE yylval;\n");
X    }
X}
X
X
Xoutput_stored_text()
X{
X    register int c;
X    register FILE *in, *out;
X
X    fclose(text_file);
X    text_file = fopen(text_file_name, "r");
X    if (text_file == NULL) open_error(text_file_name);
X    in = text_file;
X    out = output_file;
X    if ((c = getc(in)) == EOF)
X	return;
X    if (c == '\n') ++outline;
X    putc(c, out);
X    while ((c = getc(in)) != EOF)
X    {
X	if (c == '\n') ++outline;
X	putc(c, out);
X    }
X    if (!lflag)
X    {
X	++outline;
X	fprintf(out, line_format, outline + 1, output_file_name);
X    }
X}
X
X
Xoutput_debug()
X{
X    register int i, j, k, max;
X    char **symnam, *s;
X
X    ++outline;
X    fprintf(output_file, "#define YYFINAL %d\n", final_state);
X    outline += 3;
X    fprintf(output_file, "#ifndef YYDEBUG\n#define YYDEBUG %d\n#endif\n",
X	    tflag);
X
X    max = 0;
X    for (i = 2; i < ntokens; ++i)
X	if (symbol_value[i] > max)
X	    max = symbol_value[i];
X    ++outline;
X    fprintf(output_file, "#define YYMAXTOKEN %d\n", max);
X
X    symnam = (char **) MALLOC((max+1)*sizeof(char *));
X    if (symnam == 0) no_space();
X    for (i = 0; i < max; ++i)
X	symnam[i] = 0;
X    for (i = ntokens - 1; i >= 2; --i)
X	symnam[symbol_value[i]] = symbol_name[i];
X    symnam[0] = "end-of-file";
X
X    ++outline;
X    fprintf(output_file, "#if YYDEBUG\nchar *yyname[] = {");
X    j = 80;
X    for (i = 0; i <= max; ++i)
X    {
X	if (s = symnam[i])
X	{
X	    if (s[0] == '"')
X	    {
X		k = 7;
X		while (*++s != '"')
X		{
X		    if (*s == '\\')
X		    {
X			k += 2;
X			if (*++s == '\\')
X			    k += 2;
X			else
X			    ++k;
X		    }
X		    else
X			++k;
X		}
X		j += k;
X		if (j > 80)
X		{
X		    ++outline;
X		    putc('\n', output_file);
X		    j = k;
X		}
X		fprintf(output_file, "\"\\\"");
X		s = symnam[i];
X		while (*++s != '"')
X		{
X		    if (*s == '\\')
X		    {
X			fprintf(output_file, "\\\\");
X			if (*++s == '\\')
X			    fprintf(output_file, "\\\\");
X			else
X			    putc(*s, output_file);
X		    }
X		    else
X			putc(*s, output_file);
X		}
X		fprintf(output_file, "\\\"\",");
X	    }
X	    else if (s[0] == '\'')
X	    {
X		if (s[1] == '"')
X		{
X		    j += 7;
X		    if (j > 80)
X		    {
X			++outline;
X			putc('\n', output_file);
X			j = 7;
X		    }
X		    fprintf(output_file, "\"'\\\"'\",");
X		}
X		else
X		{
X		    k = 5;
X		    while (*++s != '\'')
X		    {
X			if (*s == '\\')
X			{
X			    k += 2;
X			    ++s;
X			    if (*++s == '\\')
X				k += 2;
X			    else
X				++k;
X			}
X			else
X			    ++k;
X		    }
X		    j += k;
X		    if (j > 80)
X		    {
X			++outline;
X			putc('\n', output_file);
X			j = k;
X		    }
X		    fprintf(output_file, "\"'");
X		    s = symnam[i];
X		    while (*++s != '\'')
X		    {
X			if (*s == '\\')
X			{
X			    fprintf(output_file, "\\\\");
X			    if (*++s == '\\')
X				fprintf(output_file, "\\\\");
X			    else
X				putc(*s, output_file);
X			}
X			else
X			    putc(*s, output_file);
X		    }
X		    fprintf(output_file, "'\",");
X		}
X	    }
X	    else
X	    {
X		k = strlen(s) + 3;
X		j += k;
X		if (j > 80)
X		{
X		    ++outline;
X		    putc('\n', output_file);
X		    j = k;
X		}
X		putc('"', output_file);
X		do { putc(*s, output_file); } while (*++s);
X		fprintf(output_file, "\",");
X	    }
X	}
X	else
X	{
X	    j += 2;
X	    if (j > 80)
X	    {
X		++outline;
X		putc('\n', output_file);
X		j = 2;
X	    }
X	    fprintf(output_file, "0,");
X	}
X    }
X    outline += 2;
X    fprintf(output_file, "\n};\n");
X    FREE(symnam);
X
X    ++outline;
X    fprintf(output_file, "char *yyrule[] = {\n");
X    for (i = 2; i < nrules; ++i)
X    {
X	fprintf(output_file, "\"%s :", symbol_name[rlhs[i]]);
X	for (j = rrhs[i]; ritem[j] > 0; ++j)
X	{
X	    s = symbol_name[ritem[j]];
X	    if (s[0] == '"')
X	    {
X		fprintf(output_file, " \\\"");
X		while (*++s != '"')
X		{
X		    if (*s == '\\')
X		    {
X			if (s[1] == '\\')
X			    fprintf(output_file, "\\\\\\\\");
X			else
X			    fprintf(output_file, "\\\\%c", s[1]);
X			++s;
X		    }
X		    else
X			putc(*s, output_file);
X		}
X		fprintf(output_file, "\\\"");
X	    }
X	    else if (s[0] == '\'')
X	    {
X		if (s[1] == '"')
X		    fprintf(output_file, " '\\\"'");
X		else if (s[1] == '\\')
X		{
X		    if (s[2] == '\\')
X			fprintf(output_file, " '\\\\\\\\");
X		    else
X			fprintf(output_file, " '\\\\%c", s[2]);
X		    s += 2;
X		    while (*++s != '\'')
X			putc(*s, output_file);
X		    putc('\'', output_file);
X		}
X		else
X		    fprintf(output_file, " '%c'", s[1]);
X	    }
X	    else
X		fprintf(output_file, " %s", s);
X	}
X	++outline;
X	fprintf(output_file, "\",\n");
X    }
X
X    outline += 2;
X    fprintf(output_file, "};\n#endif\n");
X}
X
X
Xoutput_stype()
X{
X    if (!unionized && ntags == 0)
X    {
X	outline += 3;
X	fprintf(output_file, "#ifndef YYSTYPE\ntypedef int YYSTYPE;\n#endif\n");
X    }
X}
X
X
Xoutput_trailing_text()
X{
X    register int c, last;
X
X    if (line == 0)
X	return;
X
X    c = *cptr;
X    if (c == '\n')
X    {
X	++lineno;
X	if ((c = getc(input_file)) == EOF)
X	    return;
X	if (!lflag)
X	{
X	    ++outline;
X	    fprintf(output_file, line_format, lineno, input_file_name);
X	}
X	if (c == '\n') ++outline;
X	putc(c, output_file);
X	last = c;
X    }
X    else
X    {
X	if (!lflag)
X	{
X	    ++outline;
X	    fprintf(output_file, line_format, lineno, input_file_name);
X	}
X	do { putc(c, output_file); } while ((c = *++cptr) != '\n');
X	++outline;
X	putc('\n', output_file);
X	last = '\n';
X    }
X
X    while ((c = getc(input_file)) != EOF)
X    {
X	if (c == '\n') ++outline;
X	putc(c, output_file);
X	last = c;
X    }
X
X    if (last != '\n')
X    {
X	++outline;
X	putc('\n', output_file);
X    }
X    if (!lflag)
X    {
X	++outline;
X	fprintf(output_file, line_format, outline + 1, output_file_name);
X    }
X}
X
X
Xoutput_semantic_actions()
X{
X    register int c, last;
X
X    fclose(action_file);
X    action_file = fopen(action_file_name, "r");
X    if (action_file == NULL) open_error(action_file_name);
X
X    if ((c = getc(action_file)) == EOF)
X	return;
X    last = c;
X    if (c == '\n') ++outline;
X    putc(c, output_file);
X    while ((c = getc(action_file)) != EOF)
X    {
X	if (c == '\n') ++outline;
X	putc(c, output_file);
X	last = c;
X    }
X
X    if (last != '\n')
X    {
X	++outline;
X	putc('\n', output_file);
X    }
X    if (!lflag)
X    {
X	++outline;
X	fprintf(output_file, line_format, outline + 1, output_file_name);
X    }
X}
X
X
Xfree_itemsets()
X{
X    register core *cp, *next;
X
X    FREE(state_table);
X    for (cp = first_state; cp; cp = next)
X    {
X	next = cp->next;
X	FREE(cp);
X    }
X}
X
X
Xfree_shifts()
X{
X    register shifts *sp, *next;
X
X    FREE(shift_table);
X    for (sp = first_shift; sp; sp = next)
X    {
X	next = sp->next;
X	FREE(sp);
X    }
X}
X
X
X
Xfree_reductions()
X{
X    register reductions *rp, *next;
X
X    FREE(reduction_table);
X    for (rp = first_reduction; rp; rp = next)
X    {
X	next = rp->next;
X	FREE(rp);
X    }
X}
END_OF_FILE
if [[ 20075 -ne `wc -c <'output.c'` ]]; then
    echo shar: \"'output.c'\" unpacked with wrong size!
fi
# end of 'output.c'
fi
if test -f 'test/ftp.output' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'test/ftp.output'\"
else
echo shar: Extracting \"'test/ftp.output'\" \(22197 characters\)
sed "s/^X//" >'test/ftp.output' <<'END_OF_FILE'
X   0  $accept : cmd_list $end
X
X   1  cmd_list :
X   2           | cmd_list cmd
X   3           | cmd_list rcmd
X
X   4  cmd : USER SP username CRLF
X   5      | PASS SP password CRLF
X   6      | PORT SP host_port CRLF
X   7      | PASV CRLF
X   8      | TYPE SP type_code CRLF
X   9      | STRU SP struct_code CRLF
X  10      | MODE SP mode_code CRLF
X  11      | ALLO SP NUMBER CRLF
X  12      | ALLO SP NUMBER SP R SP NUMBER CRLF
X  13      | RETR check_login SP pathname CRLF
X  14      | STOR check_login SP pathname CRLF
X  15      | APPE check_login SP pathname CRLF
X  16      | NLST check_login CRLF
X  17      | NLST check_login SP STRING CRLF
X  18      | LIST check_login CRLF
X  19      | LIST check_login SP pathname CRLF
X  20      | STAT check_login SP pathname CRLF
X  21      | STAT CRLF
X  22      | DELE check_login SP pathname CRLF
X  23      | RNTO SP pathname CRLF
X  24      | ABOR CRLF
X  25      | CWD check_login CRLF
X  26      | CWD check_login SP pathname CRLF
X  27      | HELP CRLF
X  28      | HELP SP STRING CRLF
X  29      | NOOP CRLF
X  30      | MKD check_login SP pathname CRLF
X  31      | RMD check_login SP pathname CRLF
X  32      | PWD check_login CRLF
X  33      | CDUP check_login CRLF
X  34      | SITE SP HELP CRLF
X  35      | SITE SP HELP SP STRING CRLF
X  36      | SITE SP UMASK check_login CRLF
X  37      | SITE SP UMASK check_login SP octal_number CRLF
X  38      | SITE SP CHMOD check_login SP octal_number SP pathname CRLF
X  39      | SITE SP IDLE CRLF
X  40      | SITE SP IDLE SP NUMBER CRLF
X  41      | STOU check_login SP pathname CRLF
X  42      | SYST CRLF
X  43      | SIZE check_login SP pathname CRLF
X  44      | MDTM check_login SP pathname CRLF
X  45      | QUIT CRLF
X  46      | error CRLF
X
X  47  rcmd : RNFR check_login SP pathname CRLF
X
X  48  username : STRING
X
X  49  password :
X  50           | STRING
X
X  51  byte_size : NUMBER
X
X  52  host_port : NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER
X
X  53  form_code : N
X  54            | T
X  55            | C
X
X  56  type_code : A
X  57            | A SP form_code
X  58            | E
X  59            | E SP form_code
X  60            | I
X  61            | L
X  62            | L SP byte_size
X  63            | L byte_size
X
X  64  struct_code : F
X  65              | R
X  66              | P
X
X  67  mode_code : S
X  68            | B
X  69            | C
X
X  70  pathname : pathstring
X
X  71  pathstring : STRING
X
X  72  octal_number : NUMBER
X
X  73  check_login :
X
Xstate 0
X	$accept : . cmd_list $end  (0)
X	cmd_list : .  (1)
X
X	.  reduce 1
X
X	cmd_list  goto 1
X
X
Xstate 1
X	$accept : cmd_list . $end  (0)
X	cmd_list : cmd_list . cmd  (2)
X	cmd_list : cmd_list . rcmd  (3)
X
X	$end  accept
X	error  shift 2
X	USER  shift 3
X	PASS  shift 4
X	QUIT  shift 5
X	PORT  shift 6
X	PASV  shift 7
X	TYPE  shift 8
X	STRU  shift 9
X	MODE  shift 10
X	RETR  shift 11
X	STOR  shift 12
X	APPE  shift 13
X	ALLO  shift 14
X	RNFR  shift 15
X	RNTO  shift 16
X	ABOR  shift 17
X	DELE  shift 18
X	CWD  shift 19
X	LIST  shift 20
X	NLST  shift 21
X	SITE  shift 22
X	STAT  shift 23
X	HELP  shift 24
X	NOOP  shift 25
X	MKD  shift 26
X	RMD  shift 27
X	PWD  shift 28
X	CDUP  shift 29
X	STOU  shift 30
X	SYST  shift 31
X	SIZE  shift 32
X	MDTM  shift 33
X	.  error
X
X	cmd  goto 34
X	rcmd  goto 35
X
X
Xstate 2
X	cmd : error . CRLF  (46)
X
X	CRLF  shift 36
X	.  error
X
X
Xstate 3
X	cmd : USER . SP username CRLF  (4)
X
X	SP  shift 37
X	.  error
X
X
Xstate 4
X	cmd : PASS . SP password CRLF  (5)
X
X	SP  shift 38
X	.  error
X
X
Xstate 5
X	cmd : QUIT . CRLF  (45)
X
X	CRLF  shift 39
X	.  error
X
X
Xstate 6
X	cmd : PORT . SP host_port CRLF  (6)
X
X	SP  shift 40
X	.  error
X
X
Xstate 7
X	cmd : PASV . CRLF  (7)
X
X	CRLF  shift 41
X	.  error
X
X
Xstate 8
X	cmd : TYPE . SP type_code CRLF  (8)
X
X	SP  shift 42
X	.  error
X
X
Xstate 9
X	cmd : STRU . SP struct_code CRLF  (9)
X
X	SP  shift 43
X	.  error
X
X
Xstate 10
X	cmd : MODE . SP mode_code CRLF  (10)
X
X	SP  shift 44
X	.  error
X
X
Xstate 11
X	cmd : RETR . check_login SP pathname CRLF  (13)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 45
X
X
Xstate 12
X	cmd : STOR . check_login SP pathname CRLF  (14)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 46
X
X
Xstate 13
X	cmd : APPE . check_login SP pathname CRLF  (15)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 47
X
X
Xstate 14
X	cmd : ALLO . SP NUMBER CRLF  (11)
X	cmd : ALLO . SP NUMBER SP R SP NUMBER CRLF  (12)
X
X	SP  shift 48
X	.  error
X
X
Xstate 15
X	rcmd : RNFR . check_login SP pathname CRLF  (47)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 49
X
X
Xstate 16
X	cmd : RNTO . SP pathname CRLF  (23)
X
X	SP  shift 50
X	.  error
X
X
Xstate 17
X	cmd : ABOR . CRLF  (24)
X
X	CRLF  shift 51
X	.  error
X
X
Xstate 18
X	cmd : DELE . check_login SP pathname CRLF  (22)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 52
X
X
Xstate 19
X	cmd : CWD . check_login CRLF  (25)
X	cmd : CWD . check_login SP pathname CRLF  (26)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 53
X
X
Xstate 20
X	cmd : LIST . check_login CRLF  (18)
X	cmd : LIST . check_login SP pathname CRLF  (19)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 54
X
X
Xstate 21
X	cmd : NLST . check_login CRLF  (16)
X	cmd : NLST . check_login SP STRING CRLF  (17)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 55
X
X
Xstate 22
X	cmd : SITE . SP HELP CRLF  (34)
X	cmd : SITE . SP HELP SP STRING CRLF  (35)
X	cmd : SITE . SP UMASK check_login CRLF  (36)
X	cmd : SITE . SP UMASK check_login SP octal_number CRLF  (37)
X	cmd : SITE . SP CHMOD check_login SP octal_number SP pathname CRLF  (38)
X	cmd : SITE . SP IDLE CRLF  (39)
X	cmd : SITE . SP IDLE SP NUMBER CRLF  (40)
X
X	SP  shift 56
X	.  error
X
X
Xstate 23
X	cmd : STAT . check_login SP pathname CRLF  (20)
X	cmd : STAT . CRLF  (21)
X	check_login : .  (73)
X
X	CRLF  shift 57
X	SP  reduce 73
X
X	check_login  goto 58
X
X
Xstate 24
X	cmd : HELP . CRLF  (27)
X	cmd : HELP . SP STRING CRLF  (28)
X
X	SP  shift 59
X	CRLF  shift 60
X	.  error
X
X
Xstate 25
X	cmd : NOOP . CRLF  (29)
X
X	CRLF  shift 61
X	.  error
X
X
Xstate 26
X	cmd : MKD . check_login SP pathname CRLF  (30)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 62
X
X
Xstate 27
X	cmd : RMD . check_login SP pathname CRLF  (31)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 63
X
X
Xstate 28
X	cmd : PWD . check_login CRLF  (32)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 64
X
X
Xstate 29
X	cmd : CDUP . check_login CRLF  (33)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 65
X
X
Xstate 30
X	cmd : STOU . check_login SP pathname CRLF  (41)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 66
X
X
Xstate 31
X	cmd : SYST . CRLF  (42)
X
X	CRLF  shift 67
X	.  error
X
X
Xstate 32
X	cmd : SIZE . check_login SP pathname CRLF  (43)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 68
X
X
Xstate 33
X	cmd : MDTM . check_login SP pathname CRLF  (44)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 69
X
X
Xstate 34
X	cmd_list : cmd_list cmd .  (2)
X
X	.  reduce 2
X
X
Xstate 35
X	cmd_list : cmd_list rcmd .  (3)
X
X	.  reduce 3
X
X
Xstate 36
X	cmd : error CRLF .  (46)
X
X	.  reduce 46
X
X
Xstate 37
X	cmd : USER SP . username CRLF  (4)
X
X	STRING  shift 70
X	.  error
X
X	username  goto 71
X
X
Xstate 38
X	cmd : PASS SP . password CRLF  (5)
X	password : .  (49)
X
X	STRING  shift 72
X	CRLF  reduce 49
X
X	password  goto 73
X
X
Xstate 39
X	cmd : QUIT CRLF .  (45)
X
X	.  reduce 45
X
X
Xstate 40
X	cmd : PORT SP . host_port CRLF  (6)
X
X	NUMBER  shift 74
X	.  error
X
X	host_port  goto 75
X
X
Xstate 41
X	cmd : PASV CRLF .  (7)
X
X	.  reduce 7
X
X
Xstate 42
X	cmd : TYPE SP . type_code CRLF  (8)
X
X	A  shift 76
X	E  shift 77
X	I  shift 78
X	L  shift 79
X	.  error
X
X	type_code  goto 80
X
X
Xstate 43
X	cmd : STRU SP . struct_code CRLF  (9)
X
X	F  shift 81
X	P  shift 82
X	R  shift 83
X	.  error
X
X	struct_code  goto 84
X
X
Xstate 44
X	cmd : MODE SP . mode_code CRLF  (10)
X
X	B  shift 85
X	C  shift 86
X	S  shift 87
X	.  error
X
X	mode_code  goto 88
X
X
Xstate 45
X	cmd : RETR check_login . SP pathname CRLF  (13)
X
X	SP  shift 89
X	.  error
X
X
Xstate 46
X	cmd : STOR check_login . SP pathname CRLF  (14)
X
X	SP  shift 90
X	.  error
X
X
Xstate 47
X	cmd : APPE check_login . SP pathname CRLF  (15)
X
X	SP  shift 91
X	.  error
X
X
Xstate 48
X	cmd : ALLO SP . NUMBER CRLF  (11)
X	cmd : ALLO SP . NUMBER SP R SP NUMBER CRLF  (12)
X
X	NUMBER  shift 92
X	.  error
X
X
Xstate 49
X	rcmd : RNFR check_login . SP pathname CRLF  (47)
X
X	SP  shift 93
X	.  error
X
X
Xstate 50
X	cmd : RNTO SP . pathname CRLF  (23)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 95
X	pathstring  goto 96
X
X
Xstate 51
X	cmd : ABOR CRLF .  (24)
X
X	.  reduce 24
X
X
Xstate 52
X	cmd : DELE check_login . SP pathname CRLF  (22)
X
X	SP  shift 97
X	.  error
X
X
Xstate 53
X	cmd : CWD check_login . CRLF  (25)
X	cmd : CWD check_login . SP pathname CRLF  (26)
X
X	SP  shift 98
X	CRLF  shift 99
X	.  error
X
X
Xstate 54
X	cmd : LIST check_login . CRLF  (18)
X	cmd : LIST check_login . SP pathname CRLF  (19)
X
X	SP  shift 100
X	CRLF  shift 101
X	.  error
X
X
Xstate 55
X	cmd : NLST check_login . CRLF  (16)
X	cmd : NLST check_login . SP STRING CRLF  (17)
X
X	SP  shift 102
X	CRLF  shift 103
X	.  error
X
X
Xstate 56
X	cmd : SITE SP . HELP CRLF  (34)
X	cmd : SITE SP . HELP SP STRING CRLF  (35)
X	cmd : SITE SP . UMASK check_login CRLF  (36)
X	cmd : SITE SP . UMASK check_login SP octal_number CRLF  (37)
X	cmd : SITE SP . CHMOD check_login SP octal_number SP pathname CRLF  (38)
X	cmd : SITE SP . IDLE CRLF  (39)
X	cmd : SITE SP . IDLE SP NUMBER CRLF  (40)
X
X	HELP  shift 104
X	UMASK  shift 105
X	IDLE  shift 106
X	CHMOD  shift 107
X	.  error
X
X
Xstate 57
X	cmd : STAT CRLF .  (21)
X
X	.  reduce 21
X
X
Xstate 58
X	cmd : STAT check_login . SP pathname CRLF  (20)
X
X	SP  shift 108
X	.  error
X
X
Xstate 59
X	cmd : HELP SP . STRING CRLF  (28)
X
X	STRING  shift 109
X	.  error
X
X
Xstate 60
X	cmd : HELP CRLF .  (27)
X
X	.  reduce 27
X
X
Xstate 61
X	cmd : NOOP CRLF .  (29)
X
X	.  reduce 29
X
X
Xstate 62
X	cmd : MKD check_login . SP pathname CRLF  (30)
X
X	SP  shift 110
X	.  error
X
X
Xstate 63
X	cmd : RMD check_login . SP pathname CRLF  (31)
X
X	SP  shift 111
X	.  error
X
X
Xstate 64
X	cmd : PWD check_login . CRLF  (32)
X
X	CRLF  shift 112
X	.  error
X
X
Xstate 65
X	cmd : CDUP check_login . CRLF  (33)
X
X	CRLF  shift 113
X	.  error
X
X
Xstate 66
X	cmd : STOU check_login . SP pathname CRLF  (41)
X
X	SP  shift 114
X	.  error
X
X
Xstate 67
X	cmd : SYST CRLF .  (42)
X
X	.  reduce 42
X
X
Xstate 68
X	cmd : SIZE check_login . SP pathname CRLF  (43)
X
X	SP  shift 115
X	.  error
X
X
Xstate 69
X	cmd : MDTM check_login . SP pathname CRLF  (44)
X
X	SP  shift 116
X	.  error
X
X
Xstate 70
X	username : STRING .  (48)
X
X	.  reduce 48
X
X
Xstate 71
X	cmd : USER SP username . CRLF  (4)
X
X	CRLF  shift 117
X	.  error
X
X
Xstate 72
X	password : STRING .  (50)
X
X	.  reduce 50
X
X
Xstate 73
X	cmd : PASS SP password . CRLF  (5)
X
X	CRLF  shift 118
X	.  error
X
X
Xstate 74
X	host_port : NUMBER . COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER  (52)
X
X	COMMA  shift 119
X	.  error
X
X
Xstate 75
X	cmd : PORT SP host_port . CRLF  (6)
X
X	CRLF  shift 120
X	.  error
X
X
Xstate 76
X	type_code : A .  (56)
X	type_code : A . SP form_code  (57)
X
X	SP  shift 121
X	CRLF  reduce 56
X
X
Xstate 77
X	type_code : E .  (58)
X	type_code : E . SP form_code  (59)
X
X	SP  shift 122
X	CRLF  reduce 58
X
X
Xstate 78
X	type_code : I .  (60)
X
X	.  reduce 60
X
X
Xstate 79
X	type_code : L .  (61)
X	type_code : L . SP byte_size  (62)
X	type_code : L . byte_size  (63)
X
X	SP  shift 123
X	NUMBER  shift 124
X	CRLF  reduce 61
X
X	byte_size  goto 125
X
X
Xstate 80
X	cmd : TYPE SP type_code . CRLF  (8)
X
X	CRLF  shift 126
X	.  error
X
X
Xstate 81
X	struct_code : F .  (64)
X
X	.  reduce 64
X
X
Xstate 82
X	struct_code : P .  (66)
X
X	.  reduce 66
X
X
Xstate 83
X	struct_code : R .  (65)
X
X	.  reduce 65
X
X
Xstate 84
X	cmd : STRU SP struct_code . CRLF  (9)
X
X	CRLF  shift 127
X	.  error
X
X
Xstate 85
X	mode_code : B .  (68)
X
X	.  reduce 68
X
X
Xstate 86
X	mode_code : C .  (69)
X
X	.  reduce 69
X
X
Xstate 87
X	mode_code : S .  (67)
X
X	.  reduce 67
X
X
Xstate 88
X	cmd : MODE SP mode_code . CRLF  (10)
X
X	CRLF  shift 128
X	.  error
X
X
Xstate 89
X	cmd : RETR check_login SP . pathname CRLF  (13)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 129
X	pathstring  goto 96
X
X
Xstate 90
X	cmd : STOR check_login SP . pathname CRLF  (14)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 130
X	pathstring  goto 96
X
X
Xstate 91
X	cmd : APPE check_login SP . pathname CRLF  (15)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 131
X	pathstring  goto 96
X
X
Xstate 92
X	cmd : ALLO SP NUMBER . CRLF  (11)
X	cmd : ALLO SP NUMBER . SP R SP NUMBER CRLF  (12)
X
X	SP  shift 132
X	CRLF  shift 133
X	.  error
X
X
Xstate 93
X	rcmd : RNFR check_login SP . pathname CRLF  (47)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 134
X	pathstring  goto 96
X
X
Xstate 94
X	pathstring : STRING .  (71)
X
X	.  reduce 71
X
X
Xstate 95
X	cmd : RNTO SP pathname . CRLF  (23)
X
X	CRLF  shift 135
X	.  error
X
X
Xstate 96
X	pathname : pathstring .  (70)
X
X	.  reduce 70
X
X
Xstate 97
X	cmd : DELE check_login SP . pathname CRLF  (22)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 136
X	pathstring  goto 96
X
X
Xstate 98
X	cmd : CWD check_login SP . pathname CRLF  (26)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 137
X	pathstring  goto 96
X
X
Xstate 99
X	cmd : CWD check_login CRLF .  (25)
X
X	.  reduce 25
X
X
Xstate 100
X	cmd : LIST check_login SP . pathname CRLF  (19)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 138
X	pathstring  goto 96
X
X
Xstate 101
X	cmd : LIST check_login CRLF .  (18)
X
X	.  reduce 18
X
X
Xstate 102
X	cmd : NLST check_login SP . STRING CRLF  (17)
X
X	STRING  shift 139
X	.  error
X
X
Xstate 103
X	cmd : NLST check_login CRLF .  (16)
X
X	.  reduce 16
X
X
Xstate 104
X	cmd : SITE SP HELP . CRLF  (34)
X	cmd : SITE SP HELP . SP STRING CRLF  (35)
X
X	SP  shift 140
X	CRLF  shift 141
X	.  error
X
X
Xstate 105
X	cmd : SITE SP UMASK . check_login CRLF  (36)
X	cmd : SITE SP UMASK . check_login SP octal_number CRLF  (37)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 142
X
X
Xstate 106
X	cmd : SITE SP IDLE . CRLF  (39)
X	cmd : SITE SP IDLE . SP NUMBER CRLF  (40)
X
X	SP  shift 143
X	CRLF  shift 144
X	.  error
X
X
Xstate 107
X	cmd : SITE SP CHMOD . check_login SP octal_number SP pathname CRLF  (38)
X	check_login : .  (73)
X
X	.  reduce 73
X
X	check_login  goto 145
X
X
Xstate 108
X	cmd : STAT check_login SP . pathname CRLF  (20)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 146
X	pathstring  goto 96
X
X
Xstate 109
X	cmd : HELP SP STRING . CRLF  (28)
X
X	CRLF  shift 147
X	.  error
X
X
Xstate 110
X	cmd : MKD check_login SP . pathname CRLF  (30)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 148
X	pathstring  goto 96
X
X
Xstate 111
X	cmd : RMD check_login SP . pathname CRLF  (31)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 149
X	pathstring  goto 96
X
X
Xstate 112
X	cmd : PWD check_login CRLF .  (32)
X
X	.  reduce 32
X
X
Xstate 113
X	cmd : CDUP check_login CRLF .  (33)
X
X	.  reduce 33
X
X
Xstate 114
X	cmd : STOU check_login SP . pathname CRLF  (41)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 150
X	pathstring  goto 96
X
X
Xstate 115
X	cmd : SIZE check_login SP . pathname CRLF  (43)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 151
X	pathstring  goto 96
X
X
Xstate 116
X	cmd : MDTM check_login SP . pathname CRLF  (44)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 152
X	pathstring  goto 96
X
X
Xstate 117
X	cmd : USER SP username CRLF .  (4)
X
X	.  reduce 4
X
X
Xstate 118
X	cmd : PASS SP password CRLF .  (5)
X
X	.  reduce 5
X
X
Xstate 119
X	host_port : NUMBER COMMA . NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER  (52)
X
X	NUMBER  shift 153
X	.  error
X
X
Xstate 120
X	cmd : PORT SP host_port CRLF .  (6)
X
X	.  reduce 6
X
X
Xstate 121
X	type_code : A SP . form_code  (57)
X
X	C  shift 154
X	N  shift 155
X	T  shift 156
X	.  error
X
X	form_code  goto 157
X
X
Xstate 122
X	type_code : E SP . form_code  (59)
X
X	C  shift 154
X	N  shift 155
X	T  shift 156
X	.  error
X
X	form_code  goto 158
X
X
Xstate 123
X	type_code : L SP . byte_size  (62)
X
X	NUMBER  shift 124
X	.  error
X
X	byte_size  goto 159
X
X
Xstate 124
X	byte_size : NUMBER .  (51)
X
X	.  reduce 51
X
X
Xstate 125
X	type_code : L byte_size .  (63)
X
X	.  reduce 63
X
X
Xstate 126
X	cmd : TYPE SP type_code CRLF .  (8)
X
X	.  reduce 8
X
X
Xstate 127
X	cmd : STRU SP struct_code CRLF .  (9)
X
X	.  reduce 9
X
X
Xstate 128
X	cmd : MODE SP mode_code CRLF .  (10)
X
X	.  reduce 10
X
X
Xstate 129
X	cmd : RETR check_login SP pathname . CRLF  (13)
X
X	CRLF  shift 160
X	.  error
X
X
Xstate 130
X	cmd : STOR check_login SP pathname . CRLF  (14)
X
X	CRLF  shift 161
X	.  error
X
X
Xstate 131
X	cmd : APPE check_login SP pathname . CRLF  (15)
X
X	CRLF  shift 162
X	.  error
X
X
Xstate 132
X	cmd : ALLO SP NUMBER SP . R SP NUMBER CRLF  (12)
X
X	R  shift 163
X	.  error
X
X
Xstate 133
X	cmd : ALLO SP NUMBER CRLF .  (11)
X
X	.  reduce 11
X
X
Xstate 134
X	rcmd : RNFR check_login SP pathname . CRLF  (47)
X
X	CRLF  shift 164
X	.  error
X
X
Xstate 135
X	cmd : RNTO SP pathname CRLF .  (23)
X
X	.  reduce 23
X
X
Xstate 136
X	cmd : DELE check_login SP pathname . CRLF  (22)
X
X	CRLF  shift 165
X	.  error
X
X
Xstate 137
X	cmd : CWD check_login SP pathname . CRLF  (26)
X
X	CRLF  shift 166
X	.  error
X
X
Xstate 138
X	cmd : LIST check_login SP pathname . CRLF  (19)
X
X	CRLF  shift 167
X	.  error
X
X
Xstate 139
X	cmd : NLST check_login SP STRING . CRLF  (17)
X
X	CRLF  shift 168
X	.  error
X
X
Xstate 140
X	cmd : SITE SP HELP SP . STRING CRLF  (35)
X
X	STRING  shift 169
X	.  error
X
X
Xstate 141
X	cmd : SITE SP HELP CRLF .  (34)
X
X	.  reduce 34
X
X
Xstate 142
X	cmd : SITE SP UMASK check_login . CRLF  (36)
X	cmd : SITE SP UMASK check_login . SP octal_number CRLF  (37)
X
X	SP  shift 170
X	CRLF  shift 171
X	.  error
X
X
Xstate 143
X	cmd : SITE SP IDLE SP . NUMBER CRLF  (40)
X
X	NUMBER  shift 172
X	.  error
X
X
Xstate 144
X	cmd : SITE SP IDLE CRLF .  (39)
X
X	.  reduce 39
X
X
Xstate 145
X	cmd : SITE SP CHMOD check_login . SP octal_number SP pathname CRLF  (38)
X
X	SP  shift 173
X	.  error
X
X
Xstate 146
X	cmd : STAT check_login SP pathname . CRLF  (20)
X
X	CRLF  shift 174
X	.  error
X
X
Xstate 147
X	cmd : HELP SP STRING CRLF .  (28)
X
X	.  reduce 28
X
X
Xstate 148
X	cmd : MKD check_login SP pathname . CRLF  (30)
X
X	CRLF  shift 175
X	.  error
X
X
Xstate 149
X	cmd : RMD check_login SP pathname . CRLF  (31)
X
X	CRLF  shift 176
X	.  error
X
X
Xstate 150
X	cmd : STOU check_login SP pathname . CRLF  (41)
X
X	CRLF  shift 177
X	.  error
X
X
Xstate 151
X	cmd : SIZE check_login SP pathname . CRLF  (43)
X
X	CRLF  shift 178
X	.  error
X
X
Xstate 152
X	cmd : MDTM check_login SP pathname . CRLF  (44)
X
X	CRLF  shift 179
X	.  error
X
X
Xstate 153
X	host_port : NUMBER COMMA NUMBER . COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER  (52)
X
X	COMMA  shift 180
X	.  error
X
X
Xstate 154
X	form_code : C .  (55)
X
X	.  reduce 55
X
X
Xstate 155
X	form_code : N .  (53)
X
X	.  reduce 53
X
X
Xstate 156
X	form_code : T .  (54)
X
X	.  reduce 54
X
X
Xstate 157
X	type_code : A SP form_code .  (57)
X
X	.  reduce 57
X
X
Xstate 158
X	type_code : E SP form_code .  (59)
X
X	.  reduce 59
X
X
Xstate 159
X	type_code : L SP byte_size .  (62)
X
X	.  reduce 62
X
X
Xstate 160
X	cmd : RETR check_login SP pathname CRLF .  (13)
X
X	.  reduce 13
X
X
Xstate 161
X	cmd : STOR check_login SP pathname CRLF .  (14)
X
X	.  reduce 14
X
X
Xstate 162
X	cmd : APPE check_login SP pathname CRLF .  (15)
X
X	.  reduce 15
X
X
Xstate 163
X	cmd : ALLO SP NUMBER SP R . SP NUMBER CRLF  (12)
X
X	SP  shift 181
X	.  error
X
X
Xstate 164
X	rcmd : RNFR check_login SP pathname CRLF .  (47)
X
X	.  reduce 47
X
X
Xstate 165
X	cmd : DELE check_login SP pathname CRLF .  (22)
X
X	.  reduce 22
X
X
Xstate 166
X	cmd : CWD check_login SP pathname CRLF .  (26)
X
X	.  reduce 26
X
X
Xstate 167
X	cmd : LIST check_login SP pathname CRLF .  (19)
X
X	.  reduce 19
X
X
Xstate 168
X	cmd : NLST check_login SP STRING CRLF .  (17)
X
X	.  reduce 17
X
X
Xstate 169
X	cmd : SITE SP HELP SP STRING . CRLF  (35)
X
X	CRLF  shift 182
X	.  error
X
X
Xstate 170
X	cmd : SITE SP UMASK check_login SP . octal_number CRLF  (37)
X
X	NUMBER  shift 183
X	.  error
X
X	octal_number  goto 184
X
X
Xstate 171
X	cmd : SITE SP UMASK check_login CRLF .  (36)
X
X	.  reduce 36
X
X
Xstate 172
X	cmd : SITE SP IDLE SP NUMBER . CRLF  (40)
X
X	CRLF  shift 185
X	.  error
X
X
Xstate 173
X	cmd : SITE SP CHMOD check_login SP . octal_number SP pathname CRLF  (38)
X
X	NUMBER  shift 183
X	.  error
X
X	octal_number  goto 186
X
X
Xstate 174
X	cmd : STAT check_login SP pathname CRLF .  (20)
X
X	.  reduce 20
X
X
Xstate 175
X	cmd : MKD check_login SP pathname CRLF .  (30)
X
X	.  reduce 30
X
X
Xstate 176
X	cmd : RMD check_login SP pathname CRLF .  (31)
X
X	.  reduce 31
X
X
Xstate 177
X	cmd : STOU check_login SP pathname CRLF .  (41)
X
X	.  reduce 41
X
X
Xstate 178
X	cmd : SIZE check_login SP pathname CRLF .  (43)
X
X	.  reduce 43
X
X
Xstate 179
X	cmd : MDTM check_login SP pathname CRLF .  (44)
X
X	.  reduce 44
X
X
Xstate 180
X	host_port : NUMBER COMMA NUMBER COMMA . NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER  (52)
X
X	NUMBER  shift 187
X	.  error
X
X
Xstate 181
X	cmd : ALLO SP NUMBER SP R SP . NUMBER CRLF  (12)
X
X	NUMBER  shift 188
X	.  error
X
X
Xstate 182
X	cmd : SITE SP HELP SP STRING CRLF .  (35)
X
X	.  reduce 35
X
X
Xstate 183
X	octal_number : NUMBER .  (72)
X
X	.  reduce 72
X
X
Xstate 184
X	cmd : SITE SP UMASK check_login SP octal_number . CRLF  (37)
X
X	CRLF  shift 189
X	.  error
X
X
Xstate 185
X	cmd : SITE SP IDLE SP NUMBER CRLF .  (40)
X
X	.  reduce 40
X
X
Xstate 186
X	cmd : SITE SP CHMOD check_login SP octal_number . SP pathname CRLF  (38)
X
X	SP  shift 190
X	.  error
X
X
Xstate 187
X	host_port : NUMBER COMMA NUMBER COMMA NUMBER . COMMA NUMBER COMMA NUMBER COMMA NUMBER  (52)
X
X	COMMA  shift 191
X	.  error
X
X
Xstate 188
X	cmd : ALLO SP NUMBER SP R SP NUMBER . CRLF  (12)
X
X	CRLF  shift 192
X	.  error
X
X
Xstate 189
X	cmd : SITE SP UMASK check_login SP octal_number CRLF .  (37)
X
X	.  reduce 37
X
X
Xstate 190
X	cmd : SITE SP CHMOD check_login SP octal_number SP . pathname CRLF  (38)
X
X	STRING  shift 94
X	.  error
X
X	pathname  goto 193
X	pathstring  goto 96
X
X
Xstate 191
X	host_port : NUMBER COMMA NUMBER COMMA NUMBER COMMA . NUMBER COMMA NUMBER COMMA NUMBER  (52)
X
X	NUMBER  shift 194
X	.  error
X
X
Xstate 192
X	cmd : ALLO SP NUMBER SP R SP NUMBER CRLF .  (12)
X
X	.  reduce 12
X
X
Xstate 193
X	cmd : SITE SP CHMOD check_login SP octal_number SP pathname . CRLF  (38)
X
X	CRLF  shift 195
X	.  error
X
X
Xstate 194
X	host_port : NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER . COMMA NUMBER COMMA NUMBER  (52)
X
X	COMMA  shift 196
X	.  error
X
X
Xstate 195
X	cmd : SITE SP CHMOD check_login SP octal_number SP pathname CRLF .  (38)
X
X	.  reduce 38
X
X
Xstate 196
X	host_port : NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA . NUMBER COMMA NUMBER  (52)
X
X	NUMBER  shift 197
X	.  error
X
X
Xstate 197
X	host_port : NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER . COMMA NUMBER  (52)
X
X	COMMA  shift 198
X	.  error
X
X
Xstate 198
X	host_port : NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA . NUMBER  (52)
X
X	NUMBER  shift 199
X	.  error
X
X
Xstate 199
X	host_port : NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER .  (52)
X
X	.  reduce 52
X
X
X65 terminals, 16 nonterminals
X74 grammar rules, 200 states
END_OF_FILE
if [[ 22197 -ne `wc -c <'test/ftp.output'` ]]; then
    echo shar: \"'test/ftp.output'\" unpacked with wrong size!
fi
# end of 'test/ftp.output'
fi
echo shar: End of archive 3 \(of 5\).
cp /dev/null ark3isdone
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
