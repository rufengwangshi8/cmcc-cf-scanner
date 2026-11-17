package com.cmcc.cfscanner

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class ResultAdapter(private val onClick: (ScanResult) -> Unit) :
    RecyclerView.Adapter<ResultAdapter.ViewHolder>() {

    private var items: List<ScanResult> = emptyList()

    fun submitList(list: List<ScanResult>) {
        items = list
        notifyDataSetChanged()
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val ipText: TextView = view.findViewById(R.id.ipText)
        val detailText: TextView = view.findViewById(R.id.detailText)
        val badgeText: TextView = view.findViewById(R.id.badgeText)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_result, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.ipText.text = item.ip
        val speed = item.speedMbps?.let { String.format("%.1f MB/s", it) } ?: "未测速"
        holder.detailText.text = "延迟 ${item.latencyMs}ms · 下载 $speed"
        holder.badgeText.text = "特殊线路"
        holder.itemView.setOnClickListener { onClick(item) }
    }

    override fun getItemCount(): Int = items.size
}
