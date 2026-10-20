# frozen_string_literal: true

# A minimal in-process stand-in for the redis-rb client, implementing only the commands
# SQRL::Server::Redis uses, with the same method signatures. Lua scripts are recognised
# by the tag on their first line and executed as equivalent Ruby under the same mutex,
# so they are atomic exactly as on a real server.
class FakeRedis
  Entry = Struct.new(:value, :expires_at_ms)

  def initialize
    @data = {}
    @mutex = Mutex.new
  end

  def flushdb = sync { @data.clear }
  def ping = "PONG"

  def get(key) = sync { str(key) }

  def set(key, value, ex: nil, px: nil, nx: nil, **)
    sync do
      return false if nx && live(key)

      @data[key] = Entry.new(value.to_s, ttl_deadline(ex: ex, px: px))
      "OK"
    end
  end

  def getdel(key) = sync { raw_getdel(key) }

  def del(*keys) = sync { keys.flatten.count { |k| !@data.delete(k).nil? } }

  def exists?(*keys) = sync { keys.flatten.any? { |k| live(k) } }

  def rename(old, new) = sync { raw_rename(old, new) }

  def pexpire(key, ms, **)
    sync do
      entry = live(key)
      return false unless entry

      entry.expires_at_ms = now_ms + Integer(ms)
      true
    end
  end

  def hset(key, *attrs)
    sync { raw_hset(key, flatten_attrs(attrs)) }
  end

  def hget(key, field) = sync { hash(key)[field.to_s] }
  def hgetall(key) = sync { hash(key).dup }

  def hdel(key, *fields)
    sync do
      h = hash(key)
      removed = fields.flatten.count { |f| !h.delete(f.to_s).nil? }
      @data.delete(key) if h.empty?
      removed
    end
  end

  def sadd(key, *members) = sync { members.flatten.count { |m| set_of(key).add?(m.to_s) } }
  def sismember(key, member) = sync { set_of(key).include?(member.to_s) }
  def srem(key, *members) = sync { members.flatten.count { |m| set_of(key).delete?(m.to_s) } }

  def scan_each(match: "*", &block)
    keys = sync { @data.keys.select { |k| live(k) && File.fnmatch(match, k, 0) } }
    keys.each(&block)
  end

  def eval(script, keys: [], argv: [])
    tag = script.lines.first.to_s.strip
    sync do
      case tag
      when "-- sqrl:getdel" then raw_getdel(keys[0])
      when "-- sqrl:create"
        next 0 if live(keys[0])

        raw_hset(keys[0], Hash[*argv])
        1
      when "-- sqrl:remove"
        h = hash(keys[0])
        next false if h.empty?

        @data.delete(keys[0])
        h.to_a.flatten
      when "-- sqrl:rekey"
        next false unless live(keys[0])

        raw_rename(keys[0], keys[1])
        raw_hset(keys[1], "idk" => argv[0], "suk" => argv[1], "vuk" => argv[2])
        argv[3].empty? ? hash(keys[1]).delete("ins") : raw_hset(keys[1], "ins" => argv[3])
        set_of(keys[2]).add(argv[4])
        hash(keys[1]).to_a.flatten
      when "-- sqrl:claim"
        id = str(keys[0])
        next false unless id

        @data.delete(keys[0])
        pl = argv[0] + id
        next false unless hash(pl)["cps_token"] == argv[1]

        exp = hash(pl)["cps_token_expires_at"] || ""
        hash(pl).delete("cps_token")
        hash(pl).delete("cps_token_expires_at")
        [exp, id] + hash(pl).to_a.flatten
      else
        raise ArgumentError, "FakeRedis does not know the script tagged #{tag.inspect}"
      end
    end
  end

  private

  def sync(&) = @mutex.synchronize(&)
  def now_ms = (Process.clock_gettime(Process::CLOCK_REALTIME) * 1000).to_i

  def ttl_deadline(ex:, px:)
    return now_ms + (Integer(ex) * 1000) if ex
    return now_ms + Integer(px) if px

    nil
  end

  def live(key)
    entry = @data[key]
    return nil unless entry

    if entry.expires_at_ms && entry.expires_at_ms <= now_ms
      @data.delete(key)
      return nil
    end
    entry
  end

  def str(key)
    entry = live(key)
    entry && entry.value.is_a?(String) ? entry.value : nil
  end

  def hash(key)
    entry = live(key)
    return {} unless entry
    raise "WRONGTYPE #{key}" unless entry.value.is_a?(Hash)

    entry.value
  end

  def set_of(key)
    entry = live(key)
    unless entry
      entry = Entry.new(Set.new, nil)
      @data[key] = entry
    end
    entry.value
  end

  def raw_getdel(key)
    value = str(key)
    @data.delete(key) if value
    value
  end

  def raw_rename(old, new)
    entry = live(old) or raise "ERR no such key"
    @data.delete(old)
    @data[new] = entry
    "OK"
  end

  def raw_hset(key, pairs)
    entry = live(key) || (@data[key] = Entry.new({}, nil))
    raise "WRONGTYPE #{key}" unless entry.value.is_a?(Hash)

    pairs.each { |f, v| entry.value[f.to_s] = v.to_s }
    pairs.size
  end

  def flatten_attrs(attrs)
    attrs = attrs.flatten(1)
    return attrs.first if attrs.size == 1 && attrs.first.is_a?(Hash)

    Hash[*attrs]
  end
end
