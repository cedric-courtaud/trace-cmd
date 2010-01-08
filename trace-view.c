/*
 * Copyright (C) 2009, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <gtk/gtk.h>
#include <glib-object.h>

#include "trace-cmd.h"
#include "trace-local.h"
#include "trace-view.h"
#include "trace-compat.h"
#include "cpu.h"

enum {
	COL_INDEX,
	COL_CPU,
	COL_TS,
	COL_COMM,
	COL_PID,
	COL_LAT,
	COL_EVENT,
	COL_INFO,
	NUM_COLS
};

static char* col_labels[] = {
	"#",
	"CPU",
	"Time Stamp",
	"Task",
	"PID",
	"Latency",
	"Event",
	"Info",
	NULL
};
static int col_chars[] = {
	0,	/* INDEX */
	0,	/* CPU */
	0,	/* TS */
	0,	/* COMM */
	0,	/* PID */
	0,	/* LAT */
	0,	/* EVENT */
	0,	/* INFO */
	0
};

static GtkTreeModel *
create_trace_view_model(struct tracecmd_input *handle)
{
	TraceViewStore *store;

	store = trace_view_store_new(handle);

	return GTK_TREE_MODEL(store);
}

static void
spin_changed(gpointer data, GtkWidget *spin)
{
	GtkTreeView *tree = data;
	GtkTreeModel *model;
	gint val, page;

	val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(spin));

	model = gtk_tree_view_get_model(tree);
	/* This can be called when we NULL out the model */
	if (!model)
		return;
	page = trace_view_store_get_page(TRACE_VIEW_STORE(model));
	if (page == val)
		return;

	g_object_ref(model);
	gtk_tree_view_set_model(tree, NULL);

	trace_view_store_set_page(TRACE_VIEW_STORE(model), val);

	gtk_tree_view_set_model(tree, model);
	g_object_unref(model);
}

void trace_view_data_func(GtkTreeViewColumn *column, GtkCellRenderer *renderer,
			  GtkTreeModel *model, GtkTreeIter *iter,
			  gpointer data)
{
	long col_num = (long)data;
	int str_len, label_len;
	gchar *text, *str;
	int new_w, x_pad;
	GValue val = {0};
	GtkWidget *view;

	PangoFontDescription *pfd;
	PangoLayout *playout;

	/* Put the text in the renderer. */
	gtk_tree_model_get_value(model, iter, col_num, &val);
	g_object_set_property(G_OBJECT(renderer), "text", &val);

	g_object_get(G_OBJECT(renderer),
			"text", &text,
			"font-desc", &pfd,
			NULL);

	if (!text)
		goto out;

	/* Make sure there is enough room to render the column label. */
	str = text;
	str_len = strlen(str);
	label_len = strlen(col_labels[col_num]);
	if (label_len > str_len) {
		str = col_labels[col_num];
		str_len = label_len;
	}

	/* Don't bother with pango unless we have more chars than the max. */
	if (str_len > col_chars[col_num]) {
		col_chars[col_num] = str_len;

		view = GTK_WIDGET(gtk_tree_view_column_get_tree_view(column));
		playout = gtk_widget_create_pango_layout(GTK_WIDGET(view), str);
		pango_layout_set_font_description(playout, pfd);
		pango_layout_get_pixel_size(playout, &new_w, NULL);
		gtk_cell_renderer_get_padding(renderer, &x_pad, NULL);
		/* +10 to avoid another adjustment for one char */
		new_w += 2*x_pad + 10;
		g_object_unref(playout);

		if (new_w > gtk_tree_view_column_get_width(column))
			gtk_tree_view_column_set_fixed_width(column, new_w);
	}

	g_free(text);
 out:
	pango_font_description_free(pfd);
	g_value_unset(&val);
}

void
trace_view_load(GtkWidget *view, struct tracecmd_input *handle,
		GtkWidget *spin)
{
	GtkCellRenderer *renderer;
	GtkCellRenderer *fix_renderer;
	GtkTreeModel *model;


	/* --- CPU column --- */

	renderer = gtk_cell_renderer_text_new();
	fix_renderer = gtk_cell_renderer_text_new();

	g_object_set(fix_renderer,
		     "family", "Monospace",
		     "family-set", TRUE,
		     NULL);

	/*
	 * Set fixed height mode now which will cause all the columns below to
	 * be created with their sizing property to be set to
	 * GTK_TREE_VIEW_COLUMN_FIXED.
	 */
	gtk_tree_view_set_fixed_height_mode(GTK_TREE_VIEW(view), TRUE);

	for (long c = 0; c < NUM_COLS; c++)
	{
		gtk_tree_view_insert_column_with_data_func(GTK_TREE_VIEW(view),
				-1,
				col_labels[c],
				(c == COL_LAT || c == COL_INFO) ? fix_renderer : renderer,
				trace_view_data_func,
				(gpointer)c,
				NULL);
	}

	model = create_trace_view_model(handle);

	trace_view_store_set_spin_button(TRACE_VIEW_STORE(model), spin);

	g_signal_connect_swapped (G_OBJECT (spin), "value-changed",
				  G_CALLBACK (spin_changed),
				  (gpointer) view);


	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model); /* destroy model automatically with view */
}

/**
 * trace_view_get_selected_row - return the selected row
 * @treeview: The tree view
 *
 * Returns the selected row number (or -1 if none is selected)
 */
gint trace_view_get_selected_row(GtkWidget *treeview)
{
	GtkTreeView *tree = GTK_TREE_VIEW(treeview);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreePath *path;
	gchar *spath;
	GList *glist;
	gint row;

	model = gtk_tree_view_get_model(tree);
	if (!model)
		return -1;

	selection = gtk_tree_view_get_selection(tree);
	glist = gtk_tree_selection_get_selected_rows(selection, &model);
	if (!glist)
		return -1;

	/* Only one row may be selected */
	path = glist->data;
	spath = gtk_tree_path_to_string(path);
	row = atoi(spath);
	g_free(spath);

	gtk_tree_path_free(path);
	g_list_free(glist);

	return row;
}

void trace_view_make_selection_visible(GtkWidget *treeview)
{
	GtkTreeView *tree = GTK_TREE_VIEW(treeview);
	GtkTreePath *path;
	gchar *spath;
	GString *gstr;
	gint row;

	row = trace_view_get_selected_row(treeview);
	if (row < 0)
		return;

	gstr = g_string_new("");
	g_string_printf(gstr, "%d", row);
	spath = g_string_free(gstr, FALSE);

	path = gtk_tree_path_new_from_string(spath);
	g_free(spath);

	gtk_tree_view_scroll_to_cell(tree, path, NULL, TRUE, 0.5, 0.0);

	gtk_tree_path_free(path);
}

void trace_view_update_filters(GtkWidget *treeview,
			       struct filter_task *task_filter,
			       struct filter_task *hide_tasks)
{
	GtkTreeView *tree = GTK_TREE_VIEW(treeview);
	TraceViewRecord *vrec;
	GtkTreeModel *model;
	guint64 time;
	gint row;

	model = gtk_tree_view_get_model(tree);
	if (!model)
		return;

	/* Keep track of the currently selected row */
	row = trace_view_get_selected_row(treeview);
	if (row >= 0) {
		vrec = trace_view_store_get_row(TRACE_VIEW_STORE(model), row);
		time = vrec->timestamp;
	}

	g_object_ref(model);
	gtk_tree_view_set_model(tree, NULL);

	trace_view_store_assign_filters(TRACE_VIEW_STORE(model), task_filter, hide_tasks);
	trace_view_store_update_filter(TRACE_VIEW_STORE(model));

	gtk_tree_view_set_model(tree, model);
	g_object_unref(model);

	/* Keep selection near previous selection */
	if (row >= 0)
		trace_view_select(treeview, time);
}

static void select_row_from_path(GtkTreeView *tree, GtkTreePath *path)
{
	GtkTreeSelection *selection;

	selection = gtk_tree_view_get_selection(tree);
	gtk_tree_selection_select_path(selection, path);

	/* finally, make it visible */
	gtk_tree_view_scroll_to_cell(tree, path, NULL, TRUE, 0.5, 0.0);
}

void trace_view_select(GtkWidget *treeview, guint64 time)
{
	GtkTreeView *tree = GTK_TREE_VIEW(treeview);
	GtkTreeModel *model;
	GtkTreePath *path;
	gint select_page, page;
	GtkWidget *spin;
	gchar buf[100];
	gint row;

	model = gtk_tree_view_get_model(tree);
	/* This can be called when we NULL out the model */
	if (!model)
		return;

	if (!trace_view_store_visible_rows(TRACE_VIEW_STORE(model)))
		return;

	page = trace_view_store_get_page(TRACE_VIEW_STORE(model));
	select_page = trace_view_store_get_timestamp_page(TRACE_VIEW_STORE(model),
							  time);

	/* Make sure the page contains the selected event */
	if (page != select_page) {
		spin = trace_view_store_get_spin(TRACE_VIEW_STORE(model));
		/* If a spin button exists, it should update when changed */
		if (spin)
			gtk_spin_button_set_value(GTK_SPIN_BUTTON(spin), select_page);
		else {
			g_object_ref(model);
			gtk_tree_view_set_model(tree, NULL);

			trace_view_store_set_page(TRACE_VIEW_STORE(model), select_page);

			gtk_tree_view_set_model(tree, model);
			g_object_unref(model);
		}
	}

	/* Select the event */
	row = trace_view_store_get_timestamp_visible_row(TRACE_VIEW_STORE(model), time);
	snprintf(buf, 100, "%d", row);
	printf("row = %s\n", buf);
	path = gtk_tree_path_new_from_string(buf);
	select_row_from_path(tree, path);
	gtk_tree_path_free(path);
}

void trace_view_event_filter_callback(gboolean accept,
				      gboolean all_events,
				      gchar **systems,
				      gint *events,
				      gpointer data)
{
	GtkTreeView *trace_tree = data;
	GtkTreeModel *model;
	TraceViewStore *store;
	TraceViewRecord *vrec;
	guint64 time;
	gint row;
	gint i;

	if (!accept)
		return;

	model = gtk_tree_view_get_model(trace_tree);
	if (!model)
		return;

	store = TRACE_VIEW_STORE(model);

	if (all_events) {
		if (trace_view_store_get_all_events_enabled(store))
			return;

		trace_view_store_set_all_events_enabled(store);
	} else {
		trace_view_store_clear_all_events_enabled(store);

		if (systems) {
			for (i = 0; systems[i]; i++)
				trace_view_store_set_system_enabled(store, systems[i]);
		}

		if (events) {
			for (i = 0; events[i] >= 0; i++)
				trace_view_store_set_event_enabled(store, events[i]);
		}
	}

	/* Keep track of the currently selected row */
	row = trace_view_get_selected_row(GTK_WIDGET(trace_tree));
	if (row >= 0) {
		vrec = trace_view_store_get_row(store, row);
		time = vrec->timestamp;
	}

	/* Force an update */
	g_object_ref(store);
	gtk_tree_view_set_model(trace_tree, NULL);
	trace_view_store_update_filter(store);
	gtk_tree_view_set_model(trace_tree, GTK_TREE_MODEL(store));
	g_object_unref(store);

	if (row >= 0)
		trace_view_select(GTK_WIDGET(trace_tree), time);
}

void trace_view_cpu_filter_callback(gboolean accept,
				    gboolean all_cpus,
				    guint64 *selected_cpu_mask,
				    gpointer data)
{
	GtkTreeView *trace_tree = data;
	GtkTreeModel *model;
	TraceViewStore *store;
	gint cpus;
	gint cpu;

	model = gtk_tree_view_get_model(trace_tree);
	if (!model)
		return;

	store = TRACE_VIEW_STORE(model);

	if (!accept)
		return;

	g_object_ref(store);
	gtk_tree_view_set_model(trace_tree, NULL);

	if (all_cpus) {
		trace_view_store_set_all_cpus(store);
		goto set_model;
	}

	cpus = trace_view_store_get_cpus(store);

	for (cpu = 0; cpu < cpus; cpu++) {
		if (cpu_isset(selected_cpu_mask, cpu))
			trace_view_store_set_cpu(store, cpu);
		else
			trace_view_store_clear_cpu(store, cpu);
	}

 set_model:
	gtk_tree_view_set_model(trace_tree, GTK_TREE_MODEL(store));
	g_object_unref(store);
}

static GtkTreeModel *create_col_model(GtkTreeView *treeview)
{
	GtkListStore *store;
	GtkTreeViewColumn *col;
	GtkTreeIter iter;
	const gchar *title;
	int i;

	store = gtk_list_store_new(1, G_TYPE_STRING);

	i = 0;
	col = gtk_tree_view_get_column(treeview, i++);
	while (col) {
		title = gtk_tree_view_column_get_title(col);
		if (!title)
			break;

		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter,
				   0, title,
				   -1);

		col = gtk_tree_view_get_column(treeview, i++);
	}

	return GTK_TREE_MODEL(store);
}

struct search_info {
	GtkTreeView		*treeview;
	GtkWidget		*entry;
	GtkWidget		*selection;
	GtkWidget		*column;
};

#define SELECTION_NAMES					\
	C(	contains,	CONTAINS	),	\
	C(	full match,	FULL_MATCH	),	\
	C(	does not have,	NOT_IN		)

#undef C
#define C(a, b)	#a

static gchar *select_names[] = { SELECTION_NAMES, NULL };

#undef C
#define C(a, b) SEL_##b

enum select_options { SELECTION_NAMES };

static gboolean test_int(gint val, gint search_val, enum select_options sel)
{
	gint tens;
	gboolean match = TRUE;

	switch (sel) {
	case SEL_NOT_IN:
		match = FALSE;
	case SEL_CONTAINS:
		for (tens = 1; search_val / tens; tens *= 10)
			;

		while (val) {
			if (val - search_val == (val / tens) * tens)
				return match;
			val /= 10;
		}
		return !match;

	case SEL_FULL_MATCH:
		return search_val == val;
	}
	return FALSE;
}

static gboolean test_text(const gchar *text, const gchar *search_text, enum select_options sel)
{
	gboolean match = TRUE;

	switch (sel) {
	case SEL_NOT_IN:
		match = FALSE;
	case SEL_CONTAINS:

		text = strcasestr(text, search_text);
		if (text)
			return match;
		return !match;

	case SEL_FULL_MATCH:
		return strcmp(text, search_text) == 0;
	}
	return FALSE;
}

static void search_tree(gpointer data)
{
	struct search_info *info = data;
	GtkTreePath *path;
	GtkTreeViewColumn *col;
	GtkTreeModel *model;
	TraceViewStore *store;
	GtkTreeIter iter;
	GtkEntry *entry = GTK_ENTRY(info->entry);
	GtkComboBox *col_combo = GTK_COMBO_BOX(info->column);
	GtkComboBox *sel_combo = GTK_COMBO_BOX(info->selection);
	const gchar *title;
	gint val;
	gchar *text = NULL;
	const gchar *search_text;
	gint col_num;
	gint sel;
	gint search_val;
	gint start_row;
	gboolean found = FALSE;

	col_num = gtk_combo_box_get_active(col_combo);
	sel = gtk_combo_box_get_active(sel_combo);

	if (col_num >= TRACE_VIEW_STORE_N_COLUMNS)
		return;

	search_text = gtk_entry_get_text(entry);
	if (!search_text || !strlen(search_text))
		return;

	col = gtk_tree_view_get_column(info->treeview, col_num);
	if (!col)
		return;

	title = gtk_tree_view_column_get_title(col);
	if (!title)
		return;

	model = gtk_tree_view_get_model(info->treeview);
	store = TRACE_VIEW_STORE(model);

	if (!trace_view_store_visible_rows(store))
		return;

	start_row = trace_view_get_selected_row(GTK_WIDGET(info->treeview));
	if (start_row < 0)
		start_row = 0;

	if (!gtk_tree_model_iter_nth_child(model, &iter, NULL, start_row))
		return;

	search_val = atoi(search_text);
	while (gtk_tree_model_iter_next(model, &iter)) {
		switch (col_num) {
		case TRACE_VIEW_STORE_COL_INDEX:
		case TRACE_VIEW_STORE_COL_CPU:
		case TRACE_VIEW_STORE_COL_PID:
		/* integers */

			gtk_tree_model_get(model, &iter,
					   col_num, &val,
					   -1);
			if (test_int(val, search_val, sel))
				found = TRUE;
			break;

		case TRACE_VIEW_STORE_COL_TS:
		case TRACE_VIEW_STORE_COL_COMM:
		case TRACE_VIEW_STORE_COL_LAT:
		case TRACE_VIEW_STORE_COL_EVENT:
		case TRACE_VIEW_STORE_COL_INFO:
			/* strings */

			gtk_tree_model_get(model, &iter,
					   col_num, &text,
					   -1);

			if (test_text(text, search_text, sel))
				found = TRUE;
			break;
		}

		if (found)
			break;
	}


	if (!found) {
		printf("NOT FOUND!\n");
		/* show pop up */
		return;
	}

	path = gtk_tree_model_get_path(model, &iter);
	select_row_from_path(info->treeview, path);
	gtk_tree_path_free(path);
}

void trace_view_search_setup(GtkBox *box, GtkTreeView *treeview)
{
	GtkCellRenderer *renderer;
	GtkListStore *store;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *label;
	GtkWidget *col_combo;
	GtkWidget *sel_combo;
	GtkWidget *entry;
	gchar **selects = select_names;
	int i;
	struct search_info *info;

	renderer = gtk_cell_renderer_text_new();

	info = g_new0(typeof(*info), 1);
	info->treeview = treeview;

	label = gtk_label_new("Column: ");
	gtk_box_pack_start(box, label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* --- Set up the column selection combo box --- */

	model = create_col_model(treeview);

	col_combo = gtk_combo_box_new_with_model(model);
	gtk_box_pack_start(box, col_combo, FALSE, FALSE, 0);
	gtk_widget_show(col_combo);

	/* Free model with combobox */
	g_object_unref(model);

	gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(col_combo),
				   renderer,
				   TRUE);
	gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(col_combo),
				       renderer,
				       "text", 0,
				       NULL);

	gtk_combo_box_set_active(GTK_COMBO_BOX(col_combo), 0);

	info->column = col_combo;

	/* --- Set up the column selection combo box --- */

	store = gtk_list_store_new(1, G_TYPE_STRING);
	model = GTK_TREE_MODEL(store);

	sel_combo = gtk_combo_box_new_with_model(model);
	gtk_box_pack_start(box, sel_combo, FALSE, FALSE, 0);
	gtk_widget_show(sel_combo);

	info->selection = sel_combo;

	gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(sel_combo),
				   renderer,
				   TRUE);
	gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(sel_combo),
				       renderer,
				       "text", 0,
				       NULL);

	for (i = 0; selects[i]; i++ ) {
		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter,
				   0, selects[i],
				   -1);
	}

	gtk_combo_box_set_active(GTK_COMBO_BOX(sel_combo), 0);

	/* --- The text entry --- */

	entry = gtk_entry_new();
	gtk_box_pack_start(box, entry, FALSE, FALSE, 0);
	gtk_widget_show(entry);

	info->entry = entry;

	g_signal_connect_swapped (entry, "activate",
				  G_CALLBACK (search_tree),
				  (gpointer) info);
}
