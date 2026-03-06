const supabase = require('./supabaseClient')

async function testConnection() {
  const { data, error } = await supabase
    .from('users')
    .select('*')

  if (error) {
    console.log("Error:", error.message)
  } else {
    console.log("Data:", data)
  }
}

testConnection()