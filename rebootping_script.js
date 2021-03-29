function rebootping_extract_column_names(table) {
    const thead = table.getElementsByTagName('thead')[0]
    const ret = []
    for (var th of thead.getElementsByTagName('th')) {
        ret.push(th.innerHTML)
    }
    return ret
}

function rebootping_extract_column_info(tbody, column_names) {
    const ret = {}
    for (var c of column_names) {
        ret[c] = {
            column_count_strings: {},
            column_values: [],
            column_name: c,
            column_kind: null,
        }
    }
    for (var tr of tbody.getElementsByTagName('tr')) {
        var i = 0
        for (var td of tr.children) {
            const val = td.innerHTML
            const float_val = Number(val)
            const column = ret[column_names[i++]]
            if (isNaN(float_val)) {
                column.column_count_strings[val] = (column.column_count_strings[val] || 0)+1
                column.column_values.push(val)
                column.column_kind = 'column_string'
            } else {
                column.column_values.push(float_val)
                if (!column.column_kind) {
                    column.column_kind = 'column_float'
                }
            }
        }
    }
    for (var c of column_names) {
        const col = ret[c]
        col['column_quantiles'] = rebootping_quantiles(col.column_values)

        if (col.column_kind == 'column_float' && c.endsWith('_unixtime')) {
            col.column_kind = 'column_unixtime'
        }
    }
    return ret
}

function rebootping_quantiles(array) {
    const q = 100
    const sorted = array.slice(0).sort((a,b) => a-b)
    const ret = []
    for (var i = 0; i <= q; ++i) {
        const p = Math.min(Math.round((i*sorted.length)/q),sorted.length-1)        
        ret.push(sorted[p])        
    }
    return ret
}

function rebootping_axis_text_for_tick(column) {
    return {
        'column_unixtime': (tick) => {
            const ms = Math.floor(tick*1000)
            const remaining = tick*1000-ms
            const d = new Date(ms)
            return d.toLocaleString()
        }
    }[column.column_kind] || ((tick) => tick + '')
}

function rebootping_axis(info, expand_axis) {
    var data_min = info.column_quantiles[0]
    var data_max = info.column_quantiles[info.column_quantiles.length-1]
    var diff = data_max - data_min
    if (expand_axis && !diff) {
        diff = 2
        data_max = data_max + diff/2
        data_min = data_min - diff/2
    }

    var basis = Math.pow(10, Math.floor(Math.log10(diff)))

    if (info.column_kind == 'column_unixtime') {
        var adjusted_basis = basis
        for (var time_basis of [60,3600,24*3600,7*24*3600]) {
            if (basis > time_basis) {
                adjusted_basis = time_basis
            }
        }
        basis = adjusted_basis
    }

    const ret = {
        axis_min: expand_axis ? Math.floor(data_min/basis)*basis : data_min,
        axis_max: expand_axis ? Math.ceil(data_max/basis)*basis : data_max,
        axis_ticks: [],
        axis_text_for_tick: rebootping_axis_text_for_tick(info),
    }
    for (var tick = Math.ceil(ret.axis_min/basis)*basis; tick <= Math.floor(ret.axis_max/basis)*basis; tick += basis) {
        ret.axis_ticks.push(tick)
    }

    return ret
}

function rebootping_choose_y_column_name(column_infos) {
    var best_column = null
    var best_column_score = null
    for (const [name,info] of Object.entries(column_infos)) {
        if (info.column_kind != 'column_float') {
            continue
        }
        var score = info.column_quantiles[info.column_quantiles.length-1] - info.column_quantiles[0]
        var last_q = null
        for (var q of info.column_quantiles) {
            if (q != last_q) {
                score ++
                last_q = q
            }
        }

        if (null === best_column_score || score > best_column_score) {
            best_column = info
            best_column_score = score
        }
    }
    return best_column.column_name
}

function rebootping_process_table(table) {
    const column_names = rebootping_extract_column_names(table)
    const column_infos = rebootping_extract_column_info(
        table.getElementsByTagName('tbody')[0], column_names)
    const canvas = document.createElement('canvas')
    canvas.style.width = "100%"
    canvas.style.height = "20em"
    const x_col = 'event_noticed_unixtime'
    const y_col = rebootping_choose_y_column_name(column_infos) 
    const label_cols = ['ping_interface','ping_dest_addr']
    const label_ul = document.createElement('ul')

    const label_for_row = (i) => {
        var ret = y_col
        for (var name of label_cols) {
            if (!column_infos[name]) {
                continue
            }
            if (ret) {
                ret += ' '
            }
            ret += column_infos[name].column_values[i]
        }
        return ret
    }
    const colors_available = [
        '#ddf3f5',
        '#f2aaaa',
        '#e36387',
        '#C7CEEA',
        '#FFDAC1',
        '#FF9AA2',
        '#B5EAD7',
        '#957DAD',
        '#704523',
    ]
    const label_colors = {}
    const color_for_label = (label) => {
        const already = label_colors[label]
        if (already) {
            return already
        }
        const chosen = colors_available.pop()
        label_colors[label] = chosen

        const label_li = document.createElement('li')

        const label_span = document.createElement('span')
        label_span.style.backgroundColor = chosen

        label_span.innerHTML = '&nbsp;&nbsp;&nbsp;'
        label_li.appendChild(label_span)
        label_li.appendChild(document.createTextNode(' ' + label))
        label_ul.appendChild(label_li)

        return chosen
    }

    table.parentNode.insertBefore(canvas, table)
    const canvasRect = canvas.getBoundingClientRect()
    canvas.width = canvasRect.width
    canvas.height = canvasRect.height
    const ctx = canvas.getContext('2d')

    const x_axis = rebootping_axis(column_infos[x_col], true)
    const x_min = x_axis.axis_min 
    const x_max = x_axis.axis_max
    const y_axis = rebootping_axis(column_infos[y_col], true)
    const y_min = y_axis.axis_min
    const y_max = y_axis.axis_max

    var left_reserved = 0
    var bottom_reserved = 0
    const x_scale = (x) => Math.floor((x-x_min)/(x_max-x_min) * (canvas.width-left_reserved)) + left_reserved
    const y_scale = (y) => Math.floor( (canvas.height-bottom_reserved) - (y-y_min)/(y_max-y_min) * (canvas.height-bottom_reserved))

    for (var tick of y_axis.axis_ticks) {
        const text = y_axis.axis_text_for_tick(tick)
        const measured = ctx.measureText(text)
        left_reserved = Math.max(left_reserved, 1.2*measured.width)
    }
    for (var tick of x_axis.axis_ticks) {
        const x = x_scale(tick)
        const text = x_axis.axis_text_for_tick(tick)
        const measured = ctx.measureText(text)
        bottom_reserved = Math.max(bottom_reserved, 1.2*(measured.actualBoundingBoxAscent+measured.actualBoundingBoxDescent))
    }

    const x_label_measure = ctx.measureText(x_col)
    const x_label_height = 1.5*(x_label_measure.actualBoundingBoxAscent+x_label_measure.actualBoundingBoxDescent)
    const x_tick_text_start = bottom_reserved * 0.1 + x_label_height

    ctx.fillText(x_col, (canvas.width-x_label_measure.width)/2, canvas.height - x_label_height*.2)

    bottom_reserved += x_label_height

    const y_label_measure = ctx.measureText(y_col)
    const y_label_height = 1.2*(y_label_measure.actualBoundingBoxAscent+y_label_measure.actualBoundingBoxDescent)
    ctx.save()
    ctx.translate(y_label_height*0.8,canvas.height/2+y_label_measure.width/2)
    ctx.rotate(-Math.PI/2)
    ctx.fillText(y_col,0,0)
    ctx.restore()
    const y_tick_text_start = 0.8*left_reserved + 1.5*y_label_height
    left_reserved += 1.5*y_label_height

    for (var tick of y_axis.axis_ticks) {
        const y = y_scale(tick)-1
        const text = y_axis.axis_text_for_tick(tick)
        const measured = ctx.measureText(text)

        ctx.fillRect(left_reserved, y, canvas.width, 1)
        ctx.fillText(text, y_tick_text_start-measured.width, 
            Math.max(measured.actualBoundingBoxAscent,
                Math.min(y + measured.actualBoundingBoxAscent/2, canvas.height-measured.actualBoundingBoxDescent))
        )
    }

    var rightmost_text_boundary = 0
    for (var tick of x_axis.axis_ticks) {
        const x = x_scale(tick)
        const text = x_axis.axis_text_for_tick(tick)
        const measured = ctx.measureText(text)

        ctx.fillRect(x, 0, 1, canvas.height-bottom_reserved)

        const leftmost_text_boundary = x - measured.width/2
        if (leftmost_text_boundary > rightmost_text_boundary) {
            ctx.fillText(text, leftmost_text_boundary, canvas.height - x_tick_text_start) 
            rightmost_text_boundary = leftmost_text_boundary + measured.width
        } 
    }

    const x_values = column_infos[x_col].column_values
    const draw = x_values.length > canvas.width/10 ? (
        (cx,cy) => {
            ctx.fillRect(cx-1,cy,3,1)
            ctx.fillRect(cx,cy-1,1,3)
        }) : (
            (cx,cy) => {
                ctx.beginPath()
                ctx.arc(cx,cy, canvas.width/100, 0, 2*Math.PI)
                ctx.fill()
            }
        )


    for (var i = 0; i < x_values.length; ++i) {
        const x = x_values[i]
        const y = column_infos[y_col].column_values[i]
        
        const cx = x_scale(x)
        const cy = y_scale(y)

        const label = label_for_row(i)
        ctx.fillStyle = color_for_label(label)
        draw(cx, cy)
    }

    table.parentNode.insertBefore(label_ul, table)
}



function rebootping_process_html() {
    for (var table of document.getElementsByTagName('table')) {
        try {
            rebootping_process_table(table)
        } catch (e) {
            console.error("rebootping_process_table",table,e)
        }
    }       
}