# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_10_20_061839) do
  create_table "sqrl_identities", force: :cascade do |t|
    t.string "idk", null: false
    t.string "suk"
    t.string "vuk"
    t.boolean "disabled", default: false, null: false
    t.boolean "sqrlonly", default: false, null: false
    t.boolean "hardlock", default: false, null: false
    t.string "ins"
    t.integer "logins", default: 0, null: false
    t.string "user_type"
    t.bigint "user_id"
    t.string "superseded_by"
    t.datetime "last_login_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["idk"], name: "index_sqrl_identities_on_idk", unique: true
    t.index ["user_type", "user_id"], name: "index_sqrl_identities_on_user_type_and_user_id"
  end

  create_table "sqrl_nuts", force: :cascade do |t|
    t.string "nut", null: false
    t.string "pending_login_id", null: false
    t.text "expected_server", null: false
    t.string "ip"
    t.string "bound_idk"
    t.datetime "expires_at"
    t.datetime "used_at"
    t.datetime "created_at", null: false
    t.index ["expires_at"], name: "index_sqrl_nuts_on_expires_at"
    t.index ["nut"], name: "index_sqrl_nuts_on_nut", unique: true
  end

  create_table "sqrl_pending_logins", force: :cascade do |t|
    t.string "login_id", null: false
    t.string "authenticated_idk"
    t.datetime "authenticated_at"
    t.integer "btn"
    t.boolean "asked", default: false, null: false
    t.string "last_command"
    t.string "cps_token"
    t.datetime "cps_token_expires_at"
    t.string "ip"
    t.string "return_to"
    t.string "link_user_ref"
    t.boolean "ip_matched", default: false, null: false
    t.datetime "expires_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["cps_token"], name: "index_sqrl_pending_logins_on_cps_token", unique: true
    t.index ["expires_at"], name: "index_sqrl_pending_logins_on_expires_at"
    t.index ["login_id"], name: "index_sqrl_pending_logins_on_login_id", unique: true
  end

  create_table "users", force: :cascade do |t|
    t.string "email", default: "", null: false
    t.string "encrypted_password", default: "", null: false
    t.string "reset_password_token"
    t.datetime "reset_password_sent_at"
    t.datetime "remember_created_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["email"], name: "index_users_on_email", unique: true
    t.index ["reset_password_token"], name: "index_users_on_reset_password_token", unique: true
  end
end
