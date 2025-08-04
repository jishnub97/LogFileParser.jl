module LogFileParser

using BitFlags

function parse_structured_logs(filepath::String;
        schema::NamedTuple=(;),
        filter_msg::Union{Nothing,String}=nothing,
        filter_module::Union{Nothing,String}=nothing,
        )

    parsed_entries = Vector{Dict{String, Any}}()
    current_entry = Vector{String}()

    for line in eachline(filepath)
        is_new_entry = startswith(line, '┌') || occursin(r"^\[\s*\w+:\s", line)
        if is_new_entry && !isempty(current_entry)
            flush_entry!(parsed_entries, current_entry, schema; filter_msg, filter_module)
        end
        push!(current_entry, line)
    end

    flush_entry!(parsed_entries, current_entry, schema; filter_msg, filter_module)

    return parsed_entries
end

function flush_entry!(parsed_entries::Vector{Dict{String, Any}},
                      current_entry::Vector{String},
                      schema::NamedTuple;
                      filter_msg::Union{Nothing,String},
                      filter_module::Union{Nothing,String},
                      )
    if isempty(current_entry)
        return
    end

    first_line = current_entry[1]

    result = if startswith(first_line, '┌')
        parse_structured(current_entry, schema; filter_msg, filter_module)
    elseif occursin(r"^\[\s*\w+:\s", first_line)
        parse_single_line(first_line; filter_msg)
    else
        nothing
    end

    if result !== nothing
        push!(parsed_entries, result)
    end

    empty!(current_entry)
end

function parse_structured(entry_lines::Vector{String},
                          schema::NamedTuple;
                          filter_msg::Union{Nothing,String},
                          filter_module::Union{Nothing,String},
                          )
    entry = Dict{String, Any}()

    header_match = match(r"┌ (\w+): (.+)", entry_lines[1])
    if header_match === nothing
        return nothing
    end
    level, message = header_match.captures
    entry["level"] = level
    entry["message"] = message

    if filter_msg !== nothing && !occursin(filter_msg, message)
        return nothing
    end

    key_values = Dict{Symbol, Any}()
    for line in entry_lines[2:end-1]
        var_match = match(r"│\s+(\w+)\s+=\s+(.+)", line)
        if var_match !== nothing
            key_str, val_str = var_match.captures
            key = Symbol(key_str)
            if haskey(schema, key)
                T = schema[key]
                parsed_value = tryparse(T, strip(val_str))
                if parsed_value === nothing
                    return nothing
                end
                key_values[key] = parsed_value
            end
        end
    end

    if !isempty(schema) && !all(k -> haskey(key_values, k), keys(schema))
        return nothing
    end

    entry["keys"] = key_values

    footer_match = match(r"└ @ (\S+) (\S+):(\d+)", entry_lines[end])
    if footer_match !== nothing
        mod, file, line = footer_match.captures
        if filter_module !== nothing && !occursin(filter_module, mod)
            return nothing
        end
        entry["module"] = mod
        entry["file"] = file
        entry["line"] = parse(Int, line)
    end

    return entry
end

function parse_single_line(line::String;
                           filter_msg::Union{Nothing,String})
    match_obj = match(r"^\[\s*(\w+):\s+(.+?)\s*\]?$", line)
    if match_obj === nothing
        return nothing
    end
    level, message = match_obj.captures
    if filter_msg !== nothing && !occursin(filter_msg, message)
        return nothing
    end
    return Dict("level" => level, "message" => message)
end

function find_matching_keys(parsed_log_entries::Vector{Dict{String,Any}}, match_keys = Pair{String,Any}[])
    matching_entries = Dict{String,Any}[]
    for entry in parsed_log_entries
        if all(get(entry, k, nothing) == v for (k,v) in match_keys)
            push!(matching_entries, entry)
        end
    end
    return matching_entries
end

@bitflag MatchFlags::UInt8 begin
    None = 0x00
    OpeningMessage = 0x01
    ClosingMessage = 0x02
end
const BothMessages = OpeningMessage | ClosingMessage

function find_mismatched(parsed_log_entries::Vector{Dict{String,Any}}; opening_message::String, closing_message::String)
    matched = Dict(entry["keys"] => None for entry in parsed_log_entries)
    for entry in parsed_log_entries
        k = entry["keys"]
        if haskey(entry, "message") && occursin(opening_message, entry["message"])
            matched[k] |= OpeningMessage
        end
        if haskey(entry, "message") && occursin(closing_message, entry["message"])
            matched[k] |= ClosingMessage
        end
    end
    return Dict(k=>v for (k, v) in matched if v ∉ (BothMessages, None))
end

end # module LogFileParser
